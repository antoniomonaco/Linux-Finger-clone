#include "finger.h"

int main(int argc, char *argv[]) {
    uid_t uid = getuid();
    struct passwd *pwd = getpwuid(uid);
    char *username = pwd->pw_name;
    struct flag *flag = malloc(sizeof(struct flag));
    int opt;
    int num_op = 0;
    int non_option_args_idx[10];
    int non_option_count = 0;
    
    // Iterate over the operators and set the correct flags
    while ((opt = getopt(argc, argv, "slmp")) != -1) {
        num_op += 1;
        switch (opt) {
            case 's':
                flag->s_flag = 1;
                break;
            case 'l':
                flag->l_flag = 1;
                break;
            case 'm':
                flag->m_flag = 1;
                break;
            case 'p':
                flag->p_flag = 1;
                break;
        }
    }
    
    /*
    Arguments can be in any position—before, after, or in between multiple operators.
    The for loop saves the positions of each argument.
    */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            non_option_args_idx[non_option_count] = i;  // Save the indices where arguments are found
            non_option_count++;
        }
    }

    if (non_option_count > 0) {
        handle_non_option_args(argc, argv, flag, non_option_args_idx, non_option_count, pwd);
        return EXIT_SUCCESS;
    } else { // If there are no arguments, use the currently active user (who called the finger command)
        if (pwd == NULL) {
            printf("Error processing actual user: %s\n", username);
            return EXIT_FAILURE;
        }
        if (flag->l_flag != 1) {
            flag->s_flag = 1;  // If there are no operators, set the default flag to -s
        }
        print_user_info(pwd, flag, username, -1);
        return EXIT_SUCCESS;
    }
}


void read_mail_status(const char *username) {
    char mail_file[MAX_PATH_LENGTH];
    sprintf(mail_file, "/var/mail/%s", username);
    
    struct stat mail_stat;
    if (stat(mail_file, &mail_stat) == -1) {
        printf("No Mail\n");
        return;
    }

    time_t last_access_time = mail_stat.st_atime;
    time_t last_modification_time = mail_stat.st_mtime;
    time_t current_time = time(NULL);

    if (last_access_time > last_modification_time) {
        printf("Mail last read %s", ctime(&last_access_time));
    } else {
        printf("New mail received %s", ctime(&last_modification_time));
    }
}
/*
Function used to read the information contained in the .plan, .pgpkey, .project, and .forward files
*/
void read_file(const char *home_dir, char *filename) {
    char file[MAX_PATH_LENGTH];
    sprintf(file, "%s/.%s", home_dir, filename);
    FILE *f = fopen(file, "r");
    if (f == NULL && strcmp(filename, "plan") == 0) {
        printf("No plan\n");
        return;
    } else if (f == NULL) {
        return;
    }
    char line[MAX_LINE_LENGTH];
    if (strcmp(filename, "plan") == 0) {
        printf("Plan:\n");
    } else if (strcmp(filename, "project") == 0) {
        printf("Project:\n");
    } else if (strcmp(filename, "forward") == 0) {
        printf("Mail forwarded to ");
    } else if (strcmp(filename, "pgpkey") == 0) {
        printf("PGP key:\n");
    }
    
    while (fgets(line, MAX_LINE_LENGTH, f) != NULL) {
        printf("%s", line);
    }

    fclose(f);
}

void set_idle_time(const char *tty, struct user *user, int session_index) {
    struct stat tty_stat;
    char tty_path[256];
    char *buffer = malloc(256 * sizeof(char)); 
    char *short_buffer = malloc(10 * sizeof(char)); // short version used for printing with the -s operator

    snprintf(tty_path, sizeof(tty_path), "/dev/%s", tty);
    if (stat(tty_path, &tty_stat) == -1) {
        perror("Failed to get tty stat");
    }
    time_t now;
    time(&now);

    int idle_time = (int)difftime(now, tty_stat.st_atime);
    int idle_minutes = idle_time / 60;
    int idle_seconds = idle_time % 60;
    const short permission = 0220;
    // Perform a bitwise AND to check if I have write permissions or not
    int writable = ((tty_stat.st_mode & permission) == permission); // variable to check write permissions
    user->write_permission[session_index] = writable;

    if (idle_minutes >= 60) {
        int idle_hours = idle_minutes / 60;
        idle_minutes = idle_minutes % 60;
        if (idle_hours == 1) {
            snprintf(buffer, 256, "%d hour %d minutes idle", idle_hours, idle_minutes);
            snprintf(short_buffer, 10, "%d:%d", idle_hours, idle_minutes);
        } else {
            snprintf(buffer, 256, "%d hours %d minutes idle", idle_hours, idle_minutes);
            snprintf(short_buffer, 10, "%dh", idle_hours);
        }
    } else {
        snprintf(buffer, 256, "%d minutes %d seconds idle", idle_minutes, idle_seconds);
        snprintf(short_buffer, 10, "%d", idle_minutes);
    }

    user->idle_time[session_index] = buffer;
    user->short_idle[session_index] = short_buffer;
}

/*
If the user is not currently online, I look for their last login in the wtmp file, since they wouldn't be present in the utmp file
*/
void get_last_login_from_wtmp(const char *username, struct user *user) {
    struct utmpx ut;
    int fd = open("/var/log/wtmp", O_RDONLY);
    if (fd == -1) {
        perror("Error opening /var/log/wtmp");
        user->last_login[0] = strdup("No logins");
        return;
    }

    time_t last_login_time = 0;
    char *buffer = malloc(256 * sizeof(char));
    /*
    read(fd, &ut, sizeof(ut)): read reads sizeof(ut) bytes from the file descriptor fd (which is the /var/log/wtmp file) 
    and stores them in the "ut" utmpx structure. Then it checks if read has read exactly sizeof(ut) bytes.
    */
    while (read(fd, &ut, sizeof(ut)) == sizeof(ut)) {
        if (ut.ut_type == USER_PROCESS && strncmp(ut.ut_user, username, sizeof(ut.ut_user)) == 0){
            if (ut.ut_tv.tv_sec > last_login_time) {
                last_login_time = ut.ut_tv.tv_sec;
                snprintf(buffer, 256, "%s", ctime(&last_login_time));
            }
        }
    }

    close(fd);

    if (last_login_time > 0) {
        user->last_login[0] = buffer;
    } else {
        user->last_login[0] = strdup("No logins");
        free(buffer);
    }
}


void last_login(char *username, struct user *user) {
    struct utmp *ut;
    int session_count = 0;
    char *buffer;

    setutent();
    while ((ut = getutent()) != NULL) {
        if (ut->ut_type == USER_PROCESS && strncmp(ut->ut_user, username, UT_NAMESIZE) == 0) {
            session_count++;
        }
    }
    endutent();

    user->session_count = session_count;
    user->last_login = malloc(session_count * sizeof(char *));
    user->idle_time = malloc(session_count * sizeof(char *));
    user->short_idle = malloc(session_count * sizeof(char *));
    user->tty = malloc(session_count * sizeof(char *));

    int index = 0;
    setutent();
    while ((ut = getutent()) != NULL) {
        if (ut->ut_type == USER_PROCESS && strncmp(ut->ut_user, username, UT_NAMESIZE) == 0) {
            time_t login_time = (time_t)ut->ut_tv.tv_sec;
            buffer = malloc(256 * sizeof(char));
            snprintf(buffer, 256, "%s", ctime(&login_time));
            user->last_login[index] = buffer;
            user->tty[index] = strndup(ut->ut_line, UT_LINESIZE);
            set_idle_time(ut->ut_line, user, index);
            index++; //itero per tutte le istanze dello stesso username che trovo, perché ci possono essere più sessioni 
                     // attive per uno stesso utente
        }
    }
    endutent();

    if (session_count == 0) { //Non ho trovato nessuna sessione attiva dell'utente attuale
        user->last_login = malloc(sizeof(char *));
        user->last_login[0] = NULL; // Lascia inizialmente NULL
        user->tty = malloc(sizeof(char *));
        user->tty[0] = NULL;
        user->idle_time = malloc(sizeof(char *));
        user->idle_time[0] = NULL;
        user->short_idle = malloc(sizeof(char *));
        user->short_idle[0] = NULL;
        user->session_count = 1;

        // Verifico se nel file wtmp sono presenti dei login dell'utente
        get_last_login_from_wtmp(username, user);

        if (user->last_login[0] == NULL) { // Se non abbiamo trovato un ultimo login
            user->last_login[0] = strdup("No logins");
        }
    }
}
struct user *set_user_info(struct passwd *pwd, char *username) {
    struct user *user = malloc(sizeof(struct user));
    char *gecos = strdup(pwd->pw_gecos);

    user->name = strtok(gecos, ",");
    user->office = strtok(NULL, ",");
    user->office_phone = strtok(NULL, ",");
    user->home_phone = strtok(NULL, ",");

    last_login(username, user);

    return user;
}

void print_user_info(struct passwd *pwd, struct flag *flag, char *username, int idx) {
    struct user *user = set_user_info(pwd, username);
    char *login = (pwd->pw_name) ? pwd->pw_name : "*";
    char *name = (user->name) ? user->name : " ";
    char *office_phone = (user->office_phone) ? user->office_phone : "*";
    char *office = (user->office) ? user->office : "*";
    char *home_phone = (user->home_phone) ? user->home_phone : "*";
        
    // Formattazione dei numeri di telefono
    char *formatted_office_phone = format_phone_number(office_phone);
    char *formatted_home_phone = format_phone_number(home_phone);

    if (flag->s_flag == 1) {
        if (idx < 1) { // Se è la prima chiamata vado a stampare le colonne
            printf("Login\tName\tTty\tIdle\tLogin Time\tOffice\tOffice Phone\n");
        }
        for (int i = 0; i < user->session_count; i++) {
            char *last_login = user->last_login[i];
            char *tty = user->tty[i] ? user->tty[i]: "*";
            char *short_idle = user->short_idle[i] ? user->short_idle[i] : "*";
            if(user->write_permission[i] == 0){ //Vado a mettere l'asterisco all'inizio del tty se non ha i permessi di scrittura
                int new_len = strlen(tty) + 2; //1 per * e uno per \0
                char *new_tty = malloc(new_len * sizeof(char));
                new_tty[0] = '*';
                strcpy(new_tty + 1,tty);
                tty = new_tty;
            }
            if (strcmp(last_login, "No logins") != 0) { //Mi creo la versione più piccola del last login
                int len = strlen(last_login) - 13; //4 caratteri li tolgo all'inizio per il mese e 5 alla fine per l'anno (altri 4 per lo spazio e i secondi)
                char substring[len + 1]; // 1 per il terminatore '\0'
                strncpy(substring, last_login + 4, len);
                substring[len] = '\0';
                strcpy(last_login, substring);
            }
            printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", login, name, tty, short_idle, last_login, office, formatted_office_phone);
        }
    } else if (flag->l_flag == 1) {
        printf("Login: %s\n", pwd->pw_name);
        printf("Name: %s\n", (user->name ? : " "));
        if (office != "*") {
            printf("Office: %s\n", office);
        }
        if (office_phone != "*") {
            printf("Office phone: %s\n", formatted_office_phone);
        }
        if (home_phone != "*") {
            printf("Home phone: %s\n", formatted_home_phone);
        }
        printf("Directory: %s\n", pwd->pw_dir);
        printf("Shell: %s\n", pwd->pw_shell);
        bool is_active = false;

        for (int i = 0; i < user->session_count; i++) {
            if (user->tty[i] != NULL) {
                is_active = true;
                break;
            }
        }

        if (is_active) { //controllo se l'utente è attivo attualmente
            for (int i = 0; i < user->session_count; i++) {
                char *last_login = user->last_login[i];
                char *tty = user->tty[i];
                char *idle = user->idle_time[i];

                printf("On since %s (CEST) on %s from %s\n", last_login, tty, tty);
                if (idle != NULL) {
                    printf("   %s\n", idle);
                }
            }
        } else {
            if (strcmp(user->last_login[0], "No logins") == 0) {
                printf("Never logged in\n");
            } else {
                printf("Last login %s (CEST)\n", user->last_login[0]);
            }
        }

        read_file(pwd->pw_dir,"forward");
        read_mail_status(user->name);
        if (flag->p_flag != 1) {
            read_file(pwd->pw_dir,"pgpkey");
            read_file(pwd->pw_dir,"project");
            read_file(pwd->pw_dir,"plan");
        }
        printf("\n");
    }
    
    // Libero la memoria allocata
    free(formatted_office_phone);
    free(formatted_home_phone);
    cleanup_user(user);
}
/*
La funzione serve a cercare un utente tramite il fullname (o parte di esso)
*/
char **find_user(const char *name,int *num_users) {
    struct passwd *pw;
    FILE *f = fopen("/etc/passwd","r");
    char line[MAX_LINE_LENGTH];
    char **users = malloc(10*sizeof(char*)); //array con massimo 10 stringhe
    int i = 0;
    char *u;
while (fgets(line, MAX_LINE_LENGTH, f) != NULL) {
        if(strstr(line,name)){
            //printf("%s\n", line);
            u = strtok(line,":");
            users[i] = strdup(u);
            i ++;
        }
    }
    *num_users = i;
    return users; 
}

void handle_non_option_args(int argc, char *argv[], struct flag *flag, int *non_option_args_idx, int non_option_count, struct passwd *pwd) {

    for (int i = 0; i < non_option_count; i++) {
        int idx = non_option_args_idx[i];
        char *u = argv[idx];
        struct passwd *pwd = getpwnam(u);
        
        if (pwd == NULL) { //utente non trovato, provo a vedere se c'è una corrispondenza nel full name
            if (flag->m_flag != 1) { //se ho usato l'operatore -m non vado a cercare una corrispondenza nel full name
                int num_users;
                char **users = find_user(u, &num_users); 
                if (users != NULL) { //Se ho una corrispondenza, procedo a stamparmi le informazioni dell'utente
                    if (flag->l_flag != 1 && flag->s_flag != 1) { // Se non ci sono operatori, metto di default il flag su -l
                        flag->l_flag = 1;
                    }
                    for (int j = 0; j < num_users; j++) {
                        pwd = getpwnam(users[j]);
                        if (pwd != NULL) {
                            print_user_info(pwd, flag, users[j], j);
                        }
                    }
                    cleanup_users(users, num_users); //libero la memoria allocata a users
                    continue;
                } else {
                    printf("finger: %s: no such user\n", u);
                    continue;
                }
            } else {
                printf("finger: %s: no such user\n", u);
                continue;
            }
        }

        if (flag->s_flag != 1 && flag->l_flag != 1) { // Se non ho usato operatori, uso -l come default
            flag->l_flag = 1;
        }
        
        print_user_info(pwd, flag, u, i); //l'utente fornito in input è stato trovato, procedo normalmente con la stampa
    }
}

char *format_phone_number(char *phone_number) {
    char *formatted_number = malloc(15 * sizeof(char)); // Max length with formatting

    if (strlen(phone_number) == 10) {
        snprintf(formatted_number, 15, "%c%c%c-%c%c%c-%c%c%c%c",
                 phone_number[0], phone_number[1], phone_number[2],
                 phone_number[3], phone_number[4], phone_number[5],
                 phone_number[6], phone_number[7], phone_number[8],
                 phone_number[9]);
    } else {
        strcpy(formatted_number, phone_number); // If not 10 characters, return as is
    }

    return formatted_number;
}

void cleanup_user(struct user *user) {
    free(user->name);

    for (int i = 0; i < user->session_count; i++) {
        free(user->last_login[i]);
        free(user->idle_time[i]);
        free(user->short_idle[i]);
        free(user->tty[i]);
    }

    free(user->last_login);
    free(user->idle_time);
    free(user->short_idle);
    free(user->tty);

    free(user);
}

void cleanup_users(char **users, int num_users) {
    for (int i = 0; i < num_users; i++) {
        free(users[i]);
    }

    free(users);
}