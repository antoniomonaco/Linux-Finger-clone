#ifndef FINGER_H
#define FINGER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <utmp.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdbool.h>
#include <utmpx.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_PATH_LENGTH 256
#define MAX_LINE_LENGTH 256

struct user {
    char *name;
    char *office;
    char *office_phone;
    char *home_phone;
    char **last_login;
    char **idle_time;
    char **short_idle;
    char **tty;
    int session_count;
    int write_permission[256];
};

struct flag {
    int s_flag;
    int l_flag;
    int m_flag;
    int p_flag;
};

char **find_user(const char *name, int *num_users);
void print_user_info(struct passwd *pwd, struct flag *flag, char *username, int idx);
void set_idle_time(const char *tty, struct user *user, int session_index);
void get_last_login_from_wtmp(const char *username, struct user *user);
void last_login(char *username, struct user *user);
void read_mail_status(const char *username);
void read_file(const char *home_dir, char *filename);
struct user *set_user_info(struct passwd *pwd, char *username);
char *format_phone_number(char *phone_number);
void cleanup_user(struct user *user);
void cleanup_users(char **users, int num_users);
void handle_non_option_args(int argc, char *argv[], struct flag *flag, int *non_option_args_idx, int non_option_count, struct passwd *pwd);
char **get_active_users(int *num_users);

#endif // FINGER_H
