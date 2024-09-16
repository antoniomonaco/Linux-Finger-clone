# Finger Command Implementation

This project is a homework assignment aimed at creating a program that mimics the behavior of the Unix `finger` command, which provides information about system users. The implementation is restricted to local user information and does not include remote user lookups. Additionally, we were not allowed to use the `exec*()` family of functions in the implementation.

## Features

- **User Information**: The program fetches and displays user information such as login name, real name, office location, office phone, home phone, login time, and idle time.
- **Mail Status**: Displays whether a user has new mail or if mail has been read.
- **Plan, Project, Forward, and PGP Key Files**: Reads and displays content from `.plan`, `.project`, `.forward`, and `.pgpkey` files in the user's home directory.
- **Support for Flags**: 
  - `-s`: Displays short format of user information.
  - `-l`: Displays long format of user information.
  - `-m`: Disables matching by real name (only username lookup).
  - `-p`: Skips printing the `.pgpkey`, `.plan`, and `.project` files.
  
## Restrictions

- **Local User Information Only**: This implementation focuses solely on local users. Remote user lookups are not supported.
- **No `exec*()` Functions** have been used.
  
## Code Structure

- **Header File (`finger.h`)**: Contains variable declarations, constants, and function prototypes.
- **Source File (`finger.c`)**: Contains the main logic and function implementations.

## Compilation

To compile the program, run the following command:

```bash
gcc -o finger finger.c
```

## Usage

The program can be executed as follows:

```bash
./finger [options] [usernames...]
```

### Example Commands

1. Display information for the current user:
   ```bash
   ./finger
   ```

2. Display short information for all users:
   ```bash
   ./finger -s
   ```

3. Display detailed information for a specific user:
   ```bash
   ./finger -l username
   ```

4. Search by real name if a username is not found:
   ```bash
   ./finger partial_real_name
   ```

## Functionality Overview

- **User Information Lookup**: The program uses system calls such as `getpwuid()` and `getpwnam()` to retrieve user details.
- **Idle Time Calculation**: Idle time for a user is calculated based on the time difference between the current time and the last access time of the user’s terminal (`/dev/tty`).
- **Mail Status**: Checks the user’s mail file in `/var/mail/` to determine if new mail has been received.
- **User Sessions**: The program handles multiple sessions for a single user by checking the `/var/log/wtmp` file.

## Limitations

- The project does not support remote user lookups.
- The project only checks for user information and sessions on the local machine.
  
## License

This project is for educational purposes and does not include a specific license.
