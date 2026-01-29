#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/input.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 12345
#define MOUSE_FRAME_US 16667
#define HEARTBEAT_MS 4000 // Send a ping every 4s of silence

int g_kbd_fd = -1;
int g_mouse_fd = -1;
int g_sock_fd = -1;
volatile bool running = true;
bool is_remote = false;

int32_t acc_x = 0;
int32_t acc_y = 0;
int32_t acc_wheel = 0;

// Track the last time we sent anything to the receiver
std::chrono::steady_clock::time_point last_activity =
    std::chrono::steady_clock::now();

bool set_grab(int fd, bool grab, const char *dev_name) {
  if (fd < 0) return false;
  if (!grab) {
    ioctl(fd, EVIOCGRAB, 0);
    return true;
  }
  int attempts = 0;
  while (attempts < 5) {
    if (ioctl(fd, EVIOCGRAB, 1) == 0) return true;
    if (errno != EBUSY) {
      perror(dev_name);
      return false;
    }
    usleep(10000);
    attempts++;
  }
  std::cerr << "Failed to grab " << dev_name << std::endl;
  return false;
}

void cleanup(int signum) {
  running = false;
  if (g_kbd_fd >= 0) ioctl(g_kbd_fd, EVIOCGRAB, 0);
  if (g_mouse_fd >= 0) ioctl(g_mouse_fd, EVIOCGRAB, 0);
  if (g_sock_fd >= 0) close(g_sock_fd);
  exit(signum);
}

int connect_to_receiver(const char *ip_addr) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return -1;

  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr);

  int flag = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

  // Enable OS-level keepalives as a secondary defense
  int keepalive = 1;
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    close(sock);
    return -1;
  }
  last_activity = std::chrono::steady_clock::now();
  return sock;
}

bool send_raw_event(struct input_event *ev) {
  if (g_sock_fd < 0) return false;
  if (send(g_sock_fd, ev, sizeof(struct input_event), MSG_NOSIGNAL) < 0) {
    return false;
  }
  last_activity = std::chrono::steady_clock::now();
  return true;
}

bool send_event(uint16_t type, uint16_t code, int32_t value) {
  struct input_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = type;
  ev.code = code;
  ev.value = value;
  return send_raw_event(&ev);
}

bool flush_mouse() {
  if (g_sock_fd < 0) return true;
  bool sent_any = false;

  if (acc_x != 0) {
    send_event(EV_REL, REL_X, acc_x);
    sent_any = true;
  }
  if (acc_y != 0) {
    send_event(EV_REL, REL_Y, acc_y);
    sent_any = true;
  }
  if (acc_wheel != 0) {
    send_event(EV_REL, REL_WHEEL, acc_wheel);
    sent_any = true;
  }

  if (sent_any) {
    send_event(EV_SYN, SYN_REPORT, 0);
  }

  acc_x = 0;
  acc_y = 0;
  acc_wheel = 0;
  return true;
}

void handle_network_failure() {
  std::cerr << "Network error. Reverting to local input." << std::endl;
  is_remote = false;
  set_grab(g_kbd_fd, false, "Kbd");
  set_grab(g_mouse_fd, false, "Mouse");
  if (g_sock_fd >= 0) close(g_sock_fd);
  g_sock_fd = -1;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << " <Receiver_IP> <Kbd_Dev> <Mouse_Dev>\n";
    return 1;
  }

  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  signal(SIGPIPE, SIG_IGN);

  const char *ip_addr = argv[1];
  g_kbd_fd = open(argv[2], O_RDONLY);
  g_mouse_fd = open(argv[3], O_RDONLY);

  if (g_kbd_fd < 0 || g_mouse_fd < 0) {
    perror("Failed to open input devices");
    return 1;
  }

  std::cout << "Host started. Toggle remote with Right Alt." << std::endl;

  struct pollfd fds[2];
  fds[0].fd = g_kbd_fd;
  fds[0].events = POLLIN;
  fds[1].fd = g_mouse_fd;
  fds[1].events = POLLIN;

  auto last_toggle_time = std::chrono::steady_clock::now();
  auto last_mouse_flush = std::chrono::steady_clock::now();

  while (running) {
    auto now = std::chrono::steady_clock::now();

    // Determine how long we can wait before either a mouse flush or a heartbeat
    auto ms_since_act =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity)
            .count();
    auto us_since_flush =
        std::chrono::duration_cast<std::chrono::microseconds>(now - last_mouse_flush)
            .count();

    int next_mouse_ms = std::max(1L, (long)((MOUSE_FRAME_US - us_since_flush) / 1000));
    int next_heartbeat_ms = std::max(1L, (long)(HEARTBEAT_MS - ms_since_act));
    int poll_timeout = std::min(next_mouse_ms, next_heartbeat_ms);

    int ret = poll(fds, 2, poll_timeout);

    // 1. Check for Heartbeat (Silence timeout)
    if (g_sock_fd >= 0) {
      now = std::chrono::steady_clock::now();
      if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity)
              .count() >= HEARTBEAT_MS) {
        // Send a no-op Sync event to keep connection alive
        if (!send_event(EV_SYN, SYN_REPORT, 0)) handle_network_failure();
      }
    }

    if (ret > 0) {
      // 2. Process Keyboard
      if (fds[0].revents & POLLIN) {
        struct input_event ev;
        if (read(g_kbd_fd, &ev, sizeof(ev)) > 0) {
          if (ev.type == EV_KEY && ev.code == KEY_RIGHTALT && ev.value == 1) {
            auto t_now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    t_now - last_toggle_time)
                    .count() > 200) {
              last_toggle_time = t_now;
              if (g_sock_fd < 0) {
                g_sock_fd = connect_to_receiver(ip_addr);
                if (g_sock_fd >= 0) std::cout << "Connected!" << std::endl;
              } else {
                is_remote = !is_remote;
                if (is_remote) {
                  if (set_grab(g_kbd_fd, true, "Kbd") &&
                      set_grab(g_mouse_fd, true, "Mouse")) {
                    std::cout << ">>> REMOTE MODE <<<" << std::endl;
                  } else {
                    set_grab(g_kbd_fd, false, "Kbd");
                    set_grab(g_mouse_fd, false, "Mouse");
                    is_remote = false;
                  }
                } else {
                  set_grab(g_kbd_fd, false, "Kbd");
                  set_grab(g_mouse_fd, false, "Mouse");
                  std::cout << ">>> LOCAL MODE <<<" << std::endl;
                }
              }
            }
          } else if (is_remote && g_sock_fd >= 0) {
            if (!send_raw_event(&ev)) handle_network_failure();
          }
        }
      }

      // 3. Process Mouse
      if (fds[1].revents & POLLIN) {
        struct input_event ev;
        if (read(g_mouse_fd, &ev, sizeof(ev)) > 0 && is_remote && g_sock_fd >= 0) {
          if (ev.type == EV_REL) {
            if (ev.code == REL_X)
              acc_x += ev.value;
            else if (ev.code == REL_Y)
              acc_y += ev.value;
            else if (ev.code == REL_WHEEL)
              acc_wheel += ev.value;
          } else {
            // Flush movement before buttons
            flush_mouse();
            if (!send_raw_event(&ev)) handle_network_failure();
            // Ensure button sync
            if (ev.type == EV_KEY) send_event(EV_SYN, SYN_REPORT, 0);
          }
        }
      }
    }

    // 4. Periodic Mouse Flush
    now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::microseconds>(now - last_mouse_flush)
            .count() >= MOUSE_FRAME_US) {
      if (is_remote && g_sock_fd >= 0) {
        if (!flush_mouse()) handle_network_failure();
      }
      last_mouse_flush = now;
    }
  }

  cleanup(0);
  return 0;
}
