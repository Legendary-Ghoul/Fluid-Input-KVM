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

int g_kbd_fd = -1;
int g_mouse_fd = -1;
int g_sock_fd = -1;
volatile bool running = true;
bool is_remote = false;

int32_t acc_x = 0;
int32_t acc_y = 0;
int32_t acc_wheel = 0;

bool set_grab(int fd, bool grab, const char* dev_name) {
    if (fd < 0) return false;
    if (!grab) {
        ioctl(fd, EVIOCGRAB, 0);
        return true;
    }
    int attempts = 0;
    while (attempts < 5) {
        if (ioctl(fd, EVIOCGRAB, 1) == 0) return true;
        if (errno != EBUSY) { perror(dev_name); return false; }
        usleep(10000); 
        attempts++;
    }
    std::cerr << "Failed to grab " << dev_name << std::endl;
    return false;
}

void cleanup(int signum) {
    ioctl(g_kbd_fd, EVIOCGRAB, 0);
    ioctl(g_mouse_fd, EVIOCGRAB, 0);
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
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

bool send_event(uint16_t type, uint16_t code, int32_t value) {
    if (g_sock_fd < 0) return false;
    struct input_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    ev.code = code;
    ev.value = value;
    if (send(g_sock_fd, &ev, sizeof(ev), MSG_NOSIGNAL) < 0) return false;
    return true;
}

bool flush_mouse() {
    if (g_sock_fd < 0) return false;
    bool sent_any = false;

    if (acc_x != 0) {
        if (!send_event(EV_REL, REL_X, acc_x)) return false;
        sent_any = true;
    }
    if (acc_y != 0) {
        if (!send_event(EV_REL, REL_Y, acc_y)) return false;
        sent_any = true;
    }
    if (acc_wheel != 0) {
        if (!send_event(EV_REL, REL_WHEEL, acc_wheel)) return false;
        sent_any = true;
    }

    if (sent_any) {
        if (!send_event(EV_SYN, SYN_REPORT, 0)) return false;
    }

    acc_x = 0;
    acc_y = 0;
    acc_wheel = 0;
    return true;
}

void handle_network_failure() {
    std::cerr << "Network Error. Reverting." << std::endl;
    is_remote = false;
    set_grab(g_kbd_fd, false, "Kbd");
    set_grab(g_mouse_fd, false, "Mouse");
    close(g_sock_fd);
    g_sock_fd = -1;
    acc_x = 0; acc_y = 0; acc_wheel = 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP> <Kbd> <Mouse>\n";
        return 1;
    }

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGPIPE, SIG_IGN);

    const char* ip_addr = argv[1];
    g_kbd_fd = open(argv[2], O_RDONLY);
    g_mouse_fd = open(argv[3], O_RDONLY);

    if (g_kbd_fd < 0 || g_mouse_fd < 0) return 1;

    std::cout << "Starting... Connect via Right Alt." << std::endl;

    g_sock_fd = connect_to_client(ip_addr);
    if (g_sock_fd >= 0) std::cout << "Connected!" << std::endl;

    struct pollfd fds[2];
    fds[0].fd = g_kbd_fd;
    fds[0].events = POLLIN;
    fds[1].fd = g_mouse_fd;
    fds[1].events = POLLIN;

    struct input_event ev;
    auto last_toggle_time = std::chrono::steady_clock::now();
    auto last_mouse_flush = std::chrono::steady_clock::now();

    while (running) {
        auto now = std::chrono::steady_clock::now();
        auto us_since_flush = std::chrono::duration_cast<std::chrono::microseconds>(now - last_mouse_flush).count();
        int poll_timeout = std::max(1, (int)((MOUSE_FRAME_US - us_since_flush) / 1000));

        int ret = poll(fds, 2, poll_timeout);

        if (ret > 0 && (fds[0].revents & POLLIN)) {
            if (read(g_kbd_fd, &ev, sizeof(ev)) > 0) {
                if (ev.type == EV_KEY && ev.code == KEY_RIGHTALT && ev.value == 1) {
                    auto t_now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t_now - last_toggle_time).count();
                    if (elapsed > 200) {
                        last_toggle_time = t_now;
                        if (g_sock_fd < 0) {
                            g_sock_fd = connect_to_client(ip_addr);
                            if (g_sock_fd >= 0) std::cout << "Reconnected!" << std::endl;
                        } else {
                            bool target = !is_remote;
                            if (target) {
                                if (set_grab(g_kbd_fd, true, "Kbd") && set_grab(g_mouse_fd, true, "Mouse")) {
                                    is_remote = true;
                                    std::cout << ">>> REMOTE <<<" << std::endl;
                                } else {
                                    set_grab(g_kbd_fd, false, "Kbd"); set_grab(g_mouse_fd, false, "Mouse");
                                    is_remote = false;
                                }
                            } else {
                                is_remote = false;
                                set_grab(g_kbd_fd, false, "Kbd"); set_grab(g_mouse_fd, false, "Mouse");
                                std::cout << ">>> LOCAL <<<" << std::endl;
                            }
                        }
                    }
                    continue; 
                }

                if (is_remote && g_sock_fd >= 0) {
                    if (send(g_sock_fd, &ev, sizeof(ev), MSG_NOSIGNAL) < 0) handle_network_failure();
                }
            }
        }

        if (ret > 0 && (fds[1].revents & POLLIN)) {
            if (read(g_mouse_fd, &ev, sizeof(ev)) > 0) {
                if (is_remote && g_sock_fd >= 0) {
                    if (ev.type == EV_REL) {
                        if (ev.code == REL_X) acc_x += ev.value;
                        else if (ev.code == REL_Y) acc_y += ev.value;
                        else if (ev.code == REL_WHEEL) acc_wheel += ev.value;
                    } 
                    else if (ev.type == EV_KEY || ev.type == EV_MSC) {
                        if (!flush_mouse()) handle_network_failure();
                        if (send(g_sock_fd, &ev, sizeof(ev), MSG_NOSIGNAL) < 0) handle_network_failure();

                        if (ev.type == EV_KEY) {
                            if (!send_event(EV_SYN, SYN_REPORT, 0)) handle_network_failure();
                        }
                    }
                }
            }
        }

        now = std::chrono::steady_clock::now();
        us_since_flush = std::chrono::duration_cast<std::chrono::microseconds>(now - last_mouse_flush).count();
        if (us_since_flush >= MOUSE_FRAME_US) {
            if (is_remote && g_sock_fd >= 0) {
                if (!flush_mouse()) handle_network_failure();
            }
            last_mouse_flush = now;
        }
    }

    cleanup(0);
    return 0;
}
