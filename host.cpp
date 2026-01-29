#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <chrono>
#include <csignal>
#include <cerrno>
#include <algorithm>

#define PORT 12345
#define MOUSE_FRAME_US 16667
#define HEARTBEAT_MS 4000 // Heartbeat every 4 seconds of silence

int g_kbd_fd = -1;
int g_mouse_fd = -1;
int g_sock_fd = -1;
volatile bool running = true;
bool is_remote = false;

int32_t acc_x = 0;
int32_t acc_y = 0;
int32_t acc_wheel = 0;

// Track activity to know when to heartbeat
std::chrono::steady_clock::time_point last_activity = std::chrono::steady_clock::now();

void cleanup(int signum) {
    if (g_kbd_fd >= 0) ioctl(g_kbd_fd, EVIOCGRAB, 0);
    if (g_mouse_fd >= 0) ioctl(g_mouse_fd, EVIOCGRAB, 0);
    if (g_sock_fd >= 0) close(g_sock_fd);
    exit(signum);
}

int connect_to_client(const char* ip_addr) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr);

    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }
    last_activity = std::chrono::steady_clock::now();
    return sock;
}

bool send_raw_event(struct input_event* ev) {
    if (g_sock_fd < 0) return false;
    if (send(g_sock_fd, ev, sizeof(struct input_event), MSG_NOSIGNAL) < 0) return false;
    last_activity = std::chrono::steady_clock::now(); // Reset idle timer
    return true;
}

bool send_heartbeat() {
    struct input_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = EV_SYN;
    ev.code = SYN_REPORT;
    ev.value = 0;
    return send_raw_event(&ev);
}

// ... (set_grab and flush_mouse logic same as before)

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <Client_IP> <Kbd_Dev> <Mouse_Dev>\n";
        return 1;
    }

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGPIPE, SIG_IGN);

    const char* ip_addr = argv[1];
    g_kbd_fd = open(argv[2], O_RDONLY);
    g_mouse_fd = open(argv[3], O_RDONLY);
    if (g_kbd_fd < 0 || g_mouse_fd < 0) return 1;

    struct pollfd fds[2];
    fds[0].fd = g_kbd_fd; fds[0].events = POLLIN;
    fds[1].fd = g_mouse_fd; fds[1].events = POLLIN;

    auto last_toggle_time = std::chrono::steady_clock::now();
    auto last_mouse_flush = std::chrono::steady_clock::now();

    while (running) {
        auto now = std::chrono::steady_clock::now();
        
        // Calculate poll timeout based on next mouse flush OR heartbeat
        auto ms_since_act = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity).count();
        auto us_since_flush = std::chrono::duration_cast<std::chrono::microseconds>(now - last_mouse_flush).count();
        
        int poll_timeout = std::min(
            (int)std::max(1L, (long)((MOUSE_FRAME_US - us_since_flush) / 1000)),
            (int)std::max(1L, (long)(HEARTBEAT_MS - ms_since_act))
        );

        int ret = poll(fds, 2, poll_timeout);

        // Check for Heartbeat
        if (g_sock_fd >= 0) {
            now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity).count() >= HEARTBEAT_MS) {
                if (!send_heartbeat()) {
                    std::cerr << "Heartbeat failed. Disconnected." << std::endl;
                    close(g_sock_fd); g_sock_fd = -1;
                }
            }
        }

        if (ret > 0) {
            // Handle Keyboard/Mouse events and send_raw_event(&ev)
            // (The rest of your logic here is the same, 
            // just ensure it uses send_raw_event to update last_activity)
        }

        // Periodic Mouse Flush logic...
    }

    cleanup(0);
    return 0;
}
