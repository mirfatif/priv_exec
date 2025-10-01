// setresuid(), setresgid()
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdbool.h>

// va_start()
#include <stdarg.h>

// stdout, stderr
#include <stdio.h>

// isdigit()
#include <ctype.h>

// strtol(), getenv()
#include <stdlib.h>

// getopt_long() and 'option' struct
#include <getopt.h>

// read(), write(), close(), setresuid(), setresgid(), access(), execvp(), chown(), crypt()
#include <unistd.h>

// open() and flock() flags
#include <sys/file.h>

// strlen(), strerror(), strtok(), strcpy(), strcmp(), strncpy(), strncmp()
#include <string.h>

// mkdir(), chmod()
#include <sys/stat.h>

// Capabilities
#include <sys/capability.h>

// prctl()
#include <sys/prctl.h>

// Secure bits
#include <linux/securebits.h>

// For setgroups().
#include <grp.h>

// For user name, uid.
#include <pwd.h>

// For group name, gid.
#include <grp.h>

// For password.
#include <shadow.h>

// tcgetattr(), tcsetattr() and struct termios
#include <termios.h>

// For open() and flags.
#include <fcntl.h>

// For basename()
#include <libgen.h>

/////////////////////////////////////////////////////////////////////////

#define VERSION "v0.3"

static char *MY_NAME;

static int print_err(char *format, ...)
{
    fprintf(stderr, "%s: ", MY_NAME);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(NULL);
    return 1;
}

static int print_err_code(char *format, ...)
{
    fprintf(stderr, "%s: ", MY_NAME);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, ": %s\n", strerror(errno));
    fflush(NULL);
    return 1;
}

static int dup_error(char *str)
{
    return print_err("Duplicate %s", str);
}

static void print_out(char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(NULL);
}

static bool is_number(char *num, char *type)
{
    int len = strlen(num);
    if (!len)
        return false;

    for (int i = 0; i < len; i++)
    {
        if (!isdigit(num[i]))
        {
            if (type)
                print_err("Invalid %s: %s", type, num);
            return false;
        }
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////

static int get_last_cap()
{
    int last_cap = CAP_LAST_CAP;
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY);
    if (fd < 0)
        print_err_code("Failed to open cap_last_cap");
    else
    {
        char buf[8];
        int num = read(fd, buf, sizeof(buf));
        if (num <= 0)
            print_err_code("Failed to read cap_last_cap");
        else
        {
            num = strtoul(buf, NULL, 10);
            if (num <= 0 || num > CAP_LAST_CAP)
                print_err("Failed to parse cap_last_cap");
            else
                last_cap = num;
        }
        close(fd);
    }
    return last_cap;
}

static cap_t get_caps()
{
    cap_t caps = cap_get_proc();
    if (caps)
        return caps;

    print_err_code("Failed to interpret capabilities");
    return NULL;
}

static void print_caps(bool print_all)
{
    int last_cap = get_last_cap();

    print_out("");

    if (print_all)
    {
        fputs("All caps :", stdout);
        for (int i = 0; i <= last_cap; i++)
            fprintf(stdout, " %s(%i)", cap_to_name(i), i);
        print_out("\n");
    }

    // Effective, Inheritable and Permitted sets
    cap_t current = get_caps();
    if (current)
    {
        // https://www.man7.org/linux/man-pages/man3/cap_from_text.3.html#TEXTUAL_REPRESENTATION
        char *text = cap_to_text(current, NULL);
        if (text == NULL)
            print_err_code("Failed to textualize caps");
        else
            print_out("EIP caps    : %s", text);
        cap_free(text);
    }
    cap_free(current);

    fputs("Ambient set :", stdout);
    if (!CAP_AMBIENT_SUPPORTED())
        fputs("not supported", stdout);
    else
        for (int i = 0; i <= last_cap; i++)
            if (cap_get_ambient(i) == 1)
                fprintf(stdout, " %s(%i)", cap_to_name(i), i);
    print_out("");

    fputs("Bounding set:", stdout);
    for (int i = 0; i <= last_cap; i++)
        if (cap_get_bound(i) == 1)
            fprintf(stdout, " %s(%i)", cap_to_name(i), i);
    print_out("\n");

    int bits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    if (bits < 0)
        print_err_code("Failed to get securebits");
    else
    {
        fputs("Secure bits :", stdout);
        if (bits & SECBIT_KEEP_CAPS)
            fputs(" keep-caps", stdout);
        if (bits & SECBIT_KEEP_CAPS_LOCKED)
            fputs(" keep-caps-locked", stdout);
        if (bits & SECBIT_NO_SETUID_FIXUP)
            fputs(" no-setuid-fixup", stdout);
        if (bits & SECBIT_NO_SETUID_FIXUP_LOCKED)
            fputs(" no-setuid-fixup-locked", stdout);
        if ((bits & SECBIT_NOROOT) == 1)
            fputs(" no-root", stdout);
        if (bits & SECBIT_NOROOT_LOCKED)
            fputs(" no-root-locked", stdout);
        if (bits & SECBIT_NO_CAP_AMBIENT_RAISE)
            fputs(" no-cap-ambient-raise", stdout);
        if (bits & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)
            fputs(" no-cap-ambient-raise-locked", stdout);
        print_out("");
    }

    int r = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (r < 0)
        print_err_code("Failed to get NO_NEW_PRIVS");
    else
        print_out("no_new_privs: %s", (r == 1 ? "set" : "unset"));

    print_out("");

    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid))
        print_err_code("Failed to get uid");
    else
        print_out("resuid: %i, %i, %i", ruid, euid, suid);

    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid))
        print_err_code("Failed to get gid");
    else
        print_out("resgid: %i, %i, %i", rgid, egid, sgid);

    gid_t groups[100];
    int count = getgroups(100, groups);
    if (count < 0)
        print_err_code("Failed to get supplementary groups");
    else if (count > 0)
    {
        fputs("groups:", stdout);
        for (int i = 0; i < count; i++)
            fprintf(stdout, " %i", groups[i]);
        print_out("");
    }

    print_out("");
}

static bool has_cap(cap_t caps, const cap_value_t cap, cap_flag_t type)
{
    const cap_value_t cap_arr[1] = {cap};
    cap_flag_value_t val;
    return !cap_get_flag(caps, *cap_arr, type, &val) && val == CAP_SET;
}

static int raise_eff_cap(cap_value_t cap_p)
{
    cap_t caps = get_caps();
    if (!caps)
        return false;

    int err = 0;

    if (!has_cap(caps, cap_p, CAP_EFFECTIVE))
    {
        if (!has_cap(caps, cap_p, CAP_PERMITTED))
            err = print_err("Missing cap in permitted set: %s", cap_to_name(cap_p));
        else
        {
            const cap_value_t cap_arr[1] = {cap_p};
            cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_arr, CAP_SET);

            if (cap_set_proc(caps))
                err = print_err_code("Failed to raise %s", cap_to_name(cap_p));
        }
    }

    cap_free(caps);

    return err;
}

static void build_all_caps_str(char *all_caps_str, size_t cap_str_sz, cap_value_t *exc_caps_int_arr, int exc_cap_count)
{
    all_caps_str[0] = 0;
    char buf[cap_str_sz];

    int last_cap = get_last_cap();
    bool exc_cap;

    for (int i = 0; i <= last_cap; i++)
    {
        if (exc_caps_int_arr != NULL)
        {
            exc_cap = false;
            for (int n = 0; n < exc_cap_count; n++)
            {
                if (exc_caps_int_arr[n] == i)
                {
                    exc_cap = true;
                    break;
                }
            }

            if (exc_cap)
                continue;
        }

        strncpy(buf, all_caps_str, cap_str_sz);
        snprintf(all_caps_str, cap_str_sz, "%s%s%s", buf, cap_to_name(i), i == last_cap ? "" : ",");
    }
}

static int caps_str_to_int_(char *caps_str, int caps_count, cap_value_t *caps_int_arr)
{
    char caps_cpy[strlen(caps_str) + 1];
    strcpy(caps_cpy, caps_str);

    char *token = strtok(caps_cpy, ",");
    char cap[32];
    for (int i = 0; i < caps_count; i++)
    {
        snprintf(cap, sizeof(cap), "%s%s", strncmp("cap_", token, 4) ? "cap_" : "", token);
        if (cap_from_name(cap, &caps_int_arr[i]))
            return print_err("Bad cap: %s", token);

        token = strtok(0, ",");
    }

    return 0;
}

static int cap_count = -1;

static int caps_str_to_int(char *caps_str, cap_value_t *caps_int_arr)
{
    // Treat "+all" and "-all" as special cases.
    if (strlen(caps_str) == 4 && !strncmp("-all", caps_str, 4))
    {
        cap_count = 0;
        return 0;
    }

    size_t cap_str_sz = 1024;
    char all_caps_str[cap_str_sz];

    if ((strlen(caps_str) == 4 && !strncmp("+all", caps_str, 4)) || !strncmp("+all,-", caps_str, 6))
    {
        if (strlen(caps_str) > 4)
        {
            char *exc_caps_str = caps_str + 6;
            char exc_caps_cpy[strlen(exc_caps_str) + 1];
            strcpy(exc_caps_cpy, exc_caps_str);

            int exc_cap_count = 1;
            char *token = strtok(exc_caps_cpy, ",");
            while ((token = strtok(0, ",")))
                exc_cap_count++;

            cap_value_t exc_caps_int_arr[exc_cap_count];

            if (caps_str_to_int_(exc_caps_str, exc_cap_count, exc_caps_int_arr))
                return 1;

            build_all_caps_str(all_caps_str, cap_str_sz, exc_caps_int_arr, exc_cap_count);
        }
        else
            build_all_caps_str(all_caps_str, cap_str_sz, NULL, 0);

        caps_str = all_caps_str;
    }

    if (cap_count < 0)
    {
        char caps_cpy[strlen(caps_str) + 1];
        strcpy(caps_cpy, caps_str);

        cap_count = 1;
        char *token = strtok(caps_cpy, ",");
        while ((token = strtok(0, ",")))
            cap_count++;
    }

    if (caps_int_arr == NULL)
        return 0;

    if (caps_str_to_int_(caps_str, cap_count, caps_int_arr))
        return 1;

    return 0;
}

/*
 * Only Ambient caps are transferred to Effective (and Permitted) sets of execve()'d program:
 * (P: process, F: File)
 * P'(A)   = F(I|P|EI|EP|EIP) ? 0 : P(A)
 * P'(E) = F(E) ? P'(P) : P'(A)
 * P'(P)   = (P(I) & F(I)) | (F(P) & P(B)) | P'(A)
 *
 * So we need to raise Ambient set.
 *
 * Permitted and Inheritable sets are limiting super sets of Ambient set.
 * So we check Permitted set, and raise Inheritable set before raising Ambient set.
 *
 * Bounding set and possibly Permitted set (if lacking CAP_SETPCAP) are the limiting super sets
 * of Inheritable set if current Inheritable set doesn't have the cap (which is usually the case).
 * So we check Bounding, Inheritable and possibly Permitted sets before raising Inheritable set.
 * See "Programmatically adjusting capability sets" in
 * https://man7.org/linux/man-pages/man7/capabilities.7.html
 *
 * Effective set can also be raised for having privileges before execve().
 *
 * Permitted set is the limiting super set of Effective set.
 * So we need to check (current which is going to be new) Permitted set before raising Effective set.
 *
 * Permitted set can only be lowered. Which means
 * that new Permitted set must be a subset of current Permitted set.
 * See "Programmatically adjusting capability sets" in
 * https://man7.org/linux/man-pages/man7/capabilities.7.html
 *
 * Bounding set can only be lowered. It's a limiting super set of Permitted set gained
 * by the process after execve() if the executed file has Permitted capabilities.
 * Bounding set itself remains unchanged across execve(). Kernel starts the init process
 * with a full bounding set.
 */
static int set_caps(char *caps_str, int new_uid)
{
    // Cannot pass caps to execve()'d program without Ambient caps support.
    if (!CAP_AMBIENT_SUPPORTED())
        return print_err("Ambient caps not supported");

    raise_eff_cap(CAP_SETPCAP);

    cap_t caps = get_caps();
    if (!caps)
        return 1;

    bool has_setpcap = has_cap(caps, CAP_SETPCAP, CAP_EFFECTIVE);
    int last_cap = get_last_cap();

    // Set "cap_count".
    if (caps_str_to_int(caps_str, NULL))
        return 1;

    cap_value_t caps_int_arr[cap_count];
    if (caps_str_to_int(caps_str, caps_int_arr))
        return 1;

    /*************** INHERITABLE CAPS ***************/

    int err = 0;
    cap_value_t cap_arr[1];
    bool drop;

    for (int i = 0; i <= last_cap; i++)
    {
        drop = true;
        for (int n = 0; n < cap_count; n++)
        {
            if (caps_int_arr[n] == i)
            {
                drop = false;
                break;
            }
        }

        if (drop)
        {
            cap_arr[0] = i;
            cap_set_flag(caps, CAP_INHERITABLE, 1, cap_arr, CAP_CLEAR);
            continue;
        }

        // Required for Inheritable set if we do not have CAP_SETPCAP.
        if (!has_setpcap && !has_cap(caps, i, CAP_PERMITTED) && !has_cap(caps, i, CAP_INHERITABLE))
        {
            err = print_err("Missing cap in permitted / inheritable set: %s", cap_to_name(i));
            break;
        }

        // Required for Inheritable set.
        if (cap_get_bound(i) != CAP_SET && !has_cap(caps, i, CAP_INHERITABLE))
        {
            err = print_err("Missing cap in bounding / inheritable set: %s", cap_to_name(i));
            break;
        }

        cap_arr[0] = i;
        cap_set_flag(caps, CAP_INHERITABLE, 1, cap_arr, CAP_SET);
    }

    if (!err && cap_set_proc(caps))
        err = print_err_code("Failed to set inheritable caps");

    cap_free(caps);

    if (err)
        return err;

    /*************** AMBIENT CAPS ***************/

    // Get new (Effective, Inheritable and Permitted) caps with raised Inheritable set.
    caps = get_caps();
    if (!caps)
        return 1;

    for (int i = 0; i <= last_cap; i++)
    {
        drop = true;
        for (int n = 0; n < cap_count; n++)
        {
            if (caps_int_arr[n] == i)
            {
                drop = false;
                break;
            }
        }

        if (drop)
        {
            if (cap_set_ambient(i, CAP_CLEAR))
            {
                err = print_err_code("Failed to clear ambient cap: %s", cap_to_name(i));
                break;
            }
            continue;
        }

        // Required for Ambient set.
        if (!has_cap(caps, i, CAP_PERMITTED))
        {
            err = print_err("Missing cap in permitted set: %s", cap_to_name(i));
            break;
        }

        // Required for Ambient set.
        if (!has_cap(caps, i, CAP_INHERITABLE))
        {
            err = print_err("Missing cap in inheritable set: %s", cap_to_name(i));
            break;
        }

        if (cap_set_ambient(i, CAP_SET))
        {
            err = print_err_code("Failed to set ambient cap: %s", cap_to_name(i));
            break;
        }
    }

    cap_free(caps);

    if (err)
        return err;

    /*************** DROP BOUNDING SET ***************/

    caps = get_caps();
    if (!caps)
        return 1;

    if (!has_setpcap)
    {
        print_err("Cannot drop bounding set due to lacking setpcap");
        /*
         * When switching to root UID, dropping bounding set is required. Else the Bounding
         * set will be transferred to Effective and Permitted sets after execve(). Or SECBIT_NOROOT
         * need to be set to avoid this behavior, which also requires SETPCAP.
         *
         * See "Capabilities and execution of programs by root" in
         * https://man7.org/linux/man-pages/man7/capabilities.7.html
         *
         * Must check effective and real UID here.
         */
        if (new_uid == 0 || (getuid() == 0 && geteuid() == 0))
            return 1;
    }
    else
    {
        for (int i = 0; i <= last_cap; i++)
        {
            if (cap_drop_bound(i))
            {
                err = print_err("Failed to drop cap in bounding set: %s", cap_to_name(i));
                break;
            }
        }

        cap_free(caps);

        if (err)
            return err;
    }

    /*************** LOCK CAPS ***************/
    /*
     * Retain Permitted, Effective and Ambient set on UID change from root to non-root UID.
     * SECBIT_KEEP_CAPS retains only Permitted set. So Effective and Ambient sets need to
     * be raised after UID change.
     *
     * See "Effect of user ID changes on capabilities" and "The securebits flags" in
     * https://man7.org/linux/man-pages/man7/capabilities.7.html
     *
     * Must check effective UID here.
     */
    if (new_uid > 0 && (getuid() == 0 || geteuid() == 0))
    {
        if (!has_setpcap)
            return print_err("Cannot set no-setuid-fixup due to lacking setpcap");

        if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0))
            return print_err_code("Failed to set no_setuid_fixup security bit");
    }

    /*************** NO NEW PRIVS ***************/
    /*
     * If the execve()'d file has file capabilities, but the new process is not able to obtain the full
     * set of file permitted capabilities (b/c we have cleared Bounding set here in the calling process),
     * then execve() fails with the error EPERM.
     * See "Safety checking for capability-dumb binaries" in
     * https://man7.org/linux/man-pages/man7/capabilities.7.html
     *
     * This should be intended behavior b/c "set_priv" should not be used to execve() a program which
     * already has file capabilities.
     *
     * But in case if Bounding set is not cleared due to lacking SETPCAP, the file capabilities (if any)
     * may raise the Effective and Permitted set of new Process. So we set NO_NEW_PRIVS attrib which
     * ignores the SUID bit and/or file capabilities (if any) of the execve()'d file.
     *
     * This also saves us from handling complicated scenarios that may arise due to file capabilities,
     * SUID bit, or different R|E|S UIDs as explained under "Capabilities and execution of programs by root"
     * and "Set-user-ID-root programs that have file capabilities" in
     * https://man7.org/linux/man-pages/man7/capabilities.7.html
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return print_err_code("Failed to set no_new_privs attribute");

    return 0;
}

// To have no privileges before execve()
static int drop_permitted_caps(char *caps_str)
{
    cap_t caps = get_caps();
    if (!caps)
        return 1;

    cap_value_t caps_int_arr[cap_count];
    if (caps_str_to_int(caps_str, caps_int_arr))
        return 1;

    int last_cap = get_last_cap();
    cap_value_t cap_arr[1];
    bool drop;

    for (int i = 0; i <= last_cap; i++)
    {
        drop = true;
        for (int n = 0; n < cap_count; n++)
        {
            if (caps_int_arr[n] == i)
            {
                drop = false;
                break;
            }
        }

        // Removing cap from Permitted set will also remove it from Ambient set.
        if (!drop)
            continue;

        cap_arr[0] = i;
        cap_set_flag(caps, CAP_PERMITTED, 1, cap_arr, CAP_CLEAR);
        // Effective set must be a subset of Permitted set.
        cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_arr, CAP_CLEAR);
    }

    int err = 0;

    if (cap_set_proc(caps))
        err = print_err_code("Failed to drop permitted / effective sets");

    cap_free(caps);

    return err;
}

/////////////////////////////////////////////////////////////////////////

static int get_uid(char *user_name)
{
    errno = 0;
    struct passwd *pw = getpwnam(user_name);
    if (pw == NULL)
    {
        if (errno != 0)
            print_err_code("Failed to get user entry for %s", user_name);
        else
            print_err("Failed to get user entry for %s", user_name);

        return -1;
    }

    return pw->pw_uid;
}

static int get_gid(char *group_name)
{
    errno = 0;
    struct group *gr = getgrnam(group_name);
    if (gr == NULL)
    {
        if (errno != 0)
            print_err_code("Failed to get group entry for %s", group_name);
        else
            print_err("Failed to get group entry for %s", group_name);

        return -1;
    }

    return gr->gr_gid;
}

static int set_groups(char *groups)
{
    raise_eff_cap(CAP_SETGID);

    if (!groups)
    {
        if (setgroups(0, 0))
            return print_err_code("Failed to clear groups");
        return 0;
    }

    char groups_cpy[strlen(groups) + 1];
    strcpy(groups_cpy, groups);

    int size = 1;
    char *token = strtok(groups, ",");
    while ((token = strtok(0, ",")))
        size++;

    token = strtok(groups_cpy, ",");
    gid_t gids[size];
    for (int i = 0; i < size; i++)
    {
        if (is_number(token, NULL))
            gids[i] = strtol(token, NULL, 10);
        else
        {
            int gid = get_gid(token);
            if (gid < 0)
                return 1;
            gids[i] = gid;
        }
        token = strtok(0, ",");
    }

    if (setgroups(size, gids))
        return print_err_code("Failed to set groups");

    return 0;
}

static int set_gid(gid_t gid)
{
    raise_eff_cap(CAP_SETGID);

    if (setresgid(gid, gid, gid))
        return print_err_code("Failed to set gid");

    return 0;
}

static int set_uid(uid_t uid)
{
    raise_eff_cap(CAP_SETUID);

    if (setresuid(uid, uid, uid))
        return print_err_code("Failed to set uid");

    return 0;
}

/////////////////////////////////////////////////////////////////////////

extern char **environ;

static int exec_it(char **argv, bool keep_env, char *env)
{
    if (!keep_env)
        execvpe(argv[0], argv, NULL);
    else if (!env)
        execvp(argv[0], argv);
    else
    {
        char **e = environ;
        int count = 0;

        for (; *e; e++)
            count++;

        char *envp[count++];
        for (int i = 0; i <= count; i++)
            envp[i] = NULL;

        if (count)
        {
            count = 0;

            char *token = strtok(env, ",");
            bool found;

            while (token)
            {
                found = false;

                if (!strchr(token, '='))
                {
                    e = environ;

                    for (; *e; e++)
                    {
                        if (strncmp(*e, token, strlen(token)) || strncmp(*e + strlen(token), "=", 1))
                            continue;

                        found = false;

                        // Avoid copying duplicate variables
                        for (int i = 0; i <= count; i++)
                        {
                            if (envp[i] == NULL)
                                break;
                            else if (!strcmp(envp[i], *e))
                            {
                                found = true;
                                break;
                            }
                        }

                        if (!found)
                            envp[count++] = *e;

                        found = true;
                        break;
                    }
                }

                if (!found)
                    print_err("Invalid environment variable: %s", token);

                token = strtok(0, ",");
            }
        }

        execvpe(argv[0], argv, envp);
    }

    return print_err_code("Failed to execute %s", argv[0]);
}

/////////////////////////////////////////////////////////////////////////

static void make_session_dir(char *dir, size_t size)
{
    snprintf(dir, size, "/run/%s", MY_NAME);
}

static int authenticate(bool save_session, bool pass_prompt)
{
    // No need to authenticate if real UID is root, e.g. if run from cron or sudo.
    if (getuid() == 0)
        return 0;

    char path[128];

    if (save_session)
    {
        save_session = false;

        char cache_dir[64];
        make_session_dir(cache_dir, sizeof(cache_dir));

        if (mkdir(cache_dir, S_IRWXU) && errno != EEXIST)
            print_err_code("Failed to create directory %s", cache_dir);
        else if (chown(cache_dir, 0, 0))
            print_err_code("Failed to set ownership on %s", cache_dir);
        else if (chmod(cache_dir, S_IRWXU))
            print_err_code("Failed to set mode on %s", cache_dir);
        else
        {
            pid_t sid = getsid(0);
            if (sid == -1)
                print_err_code("Failed to get sid");
            else if (sid == 0)
                print_err("Failed to get sid");
            else
            {
                snprintf(path, sizeof(path), "%s%i%s", "/proc/", sid, "/stat");

                FILE *file;
                if ((file = fopen(path, "r")) == NULL)
                    print_err_code("Failed to open %s", path);
                else
                {
                    bool auth = false;

                    char *buf = NULL;
                    size_t buf_sz = 0;
                    ssize_t len = getline(&buf, &buf_sz, file);
                    fclose(file);

                    if (len == -1)
                        print_err_code("Failed to read %s", path);
                    else
                    {
                        // Jump to the end of 2nd field (comm)
                        char *del = strrchr(buf, ')');

                        // Jump to the start of 22nd field (starttime)
                        for (int i = 1; i <= 20; i++)
                        {
                            del = strchr(del, ' ');
                            del++;
                        }

                        char *ptr = strstr(del, " ");
                        *ptr = '\0';

                        /*
                         * "sudo" saves per-user time stamp files for credential caching.
                         * Records include user-ID, the terminal session ID, the start time of the session leader
                         * (or parent process) and current time stamp.
                         * See https://man7.org/linux/man-pages/man5/sudoers.5.html
                         *
                         * We record only SID and its start time.
                         */

                        snprintf(path, sizeof(path), "%s/%d_%s", cache_dir, sid, del);
                        // access() does not take into account file capabilities, only real UID.
                        if ((file = fopen(path, "r")))
                        {
                            fclose(file);
                            auth = true;
                        }
                        else
                            save_session = true;
                    }

                    free(buf);

                    if (auth)
                        return 0;
                }
            }
        }
    }

    // Get user name from /etc/passwd
    errno = 0;
    struct passwd *pw = getpwuid(0);
    if (pw == NULL)
    {
        if (errno != 0)
            return print_err_code("Failed to get user entry for root");

        return print_err("Failed to get user entry for root");
    }

    // Get user name from /etc/shadow
    errno = 0;
    struct spwd *spw = getspnam(pw->pw_name);
    if (spw == NULL)
    {
        if (errno == 0)
            return print_err("Failed to get passwd entry for root");

        print_err_code("Failed to get passwd entry for root");
        return errno != EACCES ? 1 : print_err("Did you 'setuid u+s' or 'setcap all+ep' me?");
    }

    struct termios old_tio;

    if (isatty(STDIN_FILENO))
    {
        if (pass_prompt)
            printf("Password for %s: ", pw->pw_name);
        else
            printf("...");
        fflush(stdout);

        if (tcgetattr(STDIN_FILENO, &old_tio))
            return print_err_code("tcgetattr()");

        struct termios new_tio = old_tio;
        new_tio.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_tio))
            return print_err_code("tcsetattr()");
    }
    else
    {
        // Don't let stdio (readline / fread / fgets / getc) read beyond the first "\n".
        // Or use read() directly. Our exec'd program might be expecting something from pipe.
        setvbuf(stdin, NULL, _IONBF, 0);
    }

    char passwd[32];
    char *pass = fgets(passwd, sizeof(passwd), stdin);

    if (isatty(STDIN_FILENO) && tcsetattr(STDIN_FILENO, TCSANOW, &old_tio))
        return print_err_code("tcsetattr()");

    if (!pass)
        return print_err("Failed to read password");

    if (isatty(STDIN_FILENO))
        print_out("");

    // Remove new line char put bt fgets()
    if (strlen(passwd) > 0 && passwd[strlen(passwd) - 1] == '\n')
        passwd[strlen(passwd) - 1] = 0;

    if (strlen(passwd) == 0)
        return print_err("Empty passwd");

    if (strcmp(spw->sp_pwdp, crypt(passwd, spw->sp_pwdp)))
        return print_err("Wrong password");

    if (save_session)
    {
        FILE *file;
        if ((file = fopen(path, "w")) == NULL)
            print_err_code("Failed to create %s", path);
        else
            fclose(file);
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////

static int copy_file(char *source, char *target)
{
    FILE *src = fopen(source, "r");
    if (src == NULL)
        return print_err_code("Failed to open %s", source);

    FILE *dst = fopen(target, "w");
    if (dst == NULL)
    {
        fclose(src);
        return print_err_code("Failed to create %s", target);
    }

    int c;
    while ((c = fgetc(src)) != EOF)
    {
        if (fputc(c, dst) == EOF)
            break;
    }

    int rc = 0;

    if (ferror(src))
        rc = print_err("Failed to read %s", source);
    else if (ferror(dst))
        rc = print_err("Failed to write to %s", target);

    fclose(src);
    fclose(dst);

    return rc;
}

/////////////////////////////////////////////////////////////////////////

static int show_usage(bool debug)
{
    char session_dir[64];
    make_session_dir(session_dir, sizeof(session_dir));

    print_out("\nUsage:");
    print_out("\t%s [options] -- <prog> [<args...>]", MY_NAME);

    print_out("");
    print_out("Authenticate with root user and execute the given program with elevated or dropped privileges.");
    print_out("Environment is cleared if we are running with SUID/SGID enabled or if UID/GID is switched.");
    print_out("Sessions are stored in %s/ directory.", session_dir);

    print_out("");
    print_out("Options:");
    print_out("\t-u|--uid=<UID>          Process user ID");
    print_out("\t-g|--gid=<GID>          Process group ID");
    print_out("\t--groups=<GROUPS>       Process groups");
    print_out("\t--caps=<CAPS>           Process capabilities");

    if (debug)
    {
        print_out("");
        print_out("\t--print-caps[=PRINT]    Print new capabilities");
    }

    print_out("");
    print_out("\t--no-save-session       Do not save terminal session");
    print_out("\t--no-prompt             Do not show password prompt");

    print_out("");
    print_out("\t-k|--keep-env[=ENV]     Keep environment");
    print_out("\t-c|--clear-env          Clear environment");

    print_out("");
    print_out("\t-V|--version            Show version");
    print_out("\t-h|--help               Show this help");

    print_out("");
    print_out("");
    print_out("\tGROUPS:");
    print_out("\t    clear | <GID1>,<GID2>,...");
    print_out("");
    print_out("\tCAPS:");
    print_out("\t    cap_<NAME1>,cap_<NAME2>,...");
    print_out("\t    +all[,-cap_<NAME1>,cap_<NAME2>,...]");
    print_out("\t    -all");
    if (debug)
    {
        print_out("");
        print_out("\tPRINT:");
        print_out("\t    all | exec");
    }
    print_out("");
    print_out("\tENV:");
    print_out("\t    <VAR1>,<VAR2>,...");
    print_out("");
    return 1;
}

/*
 * In C, 'const' qualifier does not create a compile-time constant. It merely designates
 * that a run-time variable is read-only. So we need them to be here.
 * May also define them as macros.
 */
enum
{
    DUMMY, // To start from 1
    GROUPS,
    CAPS,
    PRINT_CAPS,
    NSS,
    NPP
};

int main(int argc, char **argv)
{
    MY_NAME = basename(argv[0]);

    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Options.html
    static const struct option long_opts[] = {
        {"uid", required_argument, 0, 'u'},
        {"gid", required_argument, 0, 'g'},
        {"groups", required_argument, 0, GROUPS},
        {"caps", required_argument, 0, CAPS},
        {"print-caps", optional_argument, 0, PRINT_CAPS},
        {"no-save-session", no_argument, 0, NSS},
        {"no-prompt", no_argument, 0, NPP},
        {"keep-env", optional_argument, 0, 'k'},
        {"clear-env", no_argument, 0, 'c'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, no_argument, 0, 0}};

    int uid = -1;
    int gid = -1;
    char *groups = NULL;
    bool clear_groups = false;
    char *caps = NULL;
    bool pr_caps = false;
    bool print_all_caps = false;
    bool exec_after_pr_caps = false;
    bool no_save_session = false;
    bool no_pass_prompt = false;
    char *env = NULL;
    bool keep_env = false;
    bool clear_env = false;

    int opt = -1;

    while ((opt = getopt_long(argc, argv, "u:g:k::cVhH", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'u':
            if (uid != -1)
                return dup_error("uid");

            if (is_number(optarg, NULL))
                uid = strtol(optarg, NULL, 10);
            else
            {
                uid = get_uid(optarg);
                if (uid < 0)
                    return 1;
            }
            break;
        case 'g':
            if (gid != -1)
                return dup_error("gid");

            if (is_number(optarg, NULL))
                gid = strtol(optarg, NULL, 10);
            else
            {
                gid = get_gid(optarg);
                if (gid < 0)
                    return 1;
            }
            break;
        case GROUPS:
            if (groups)
                return dup_error("groups");
            if (strlen(optarg) == 5 && !strncmp("clear", optarg, 5))
                clear_groups = true;
            else
                groups = optarg;
            break;
        case CAPS:
            if (caps)
                return dup_error("caps");
            caps = optarg;
            break;
        case PRINT_CAPS:
            pr_caps = true;
            if (optarg)
            {
                if (!strncmp("all", optarg, 3))
                    print_all_caps = true;
                else if (!strncmp("exec", optarg, 6))
                    exec_after_pr_caps = true;
                else
                    return print_err("Bad arg to print-caps: %s", optarg);
            }
            break;
        case NSS:
            no_save_session = true;
            break;
        case NPP:
            no_pass_prompt = true;
            break;
        case 'k':
            keep_env = true;
            if (optarg)
            {
                if (!env)
                    env = strdup(optarg);
                else
                {
                    size_t le = strlen(env);
                    size_t la = strlen(optarg);
                    env = realloc(env, le + la + 2);
                    env[le] = ',';
                    memcpy(env + le + 1, optarg, la + 1);
                }
            }
            break;
        case 'c':
            clear_env = true;
            break;
        case 'V':
            print_out("%s %s", MY_NAME, VERSION);
            return 0;
        case 'h':
            show_usage(false);
            return 0;
        case 'H':
            show_usage(true);
            return 0;
        case '?':
            // "optopt" is NULL
            print_err("Bad opt: %s", argv[optind - 1]);
            return show_usage(false);
        }
    }

    char new_env[env ? strlen(env) + 1 : 0];
    if (env)
    {
        strcpy(new_env, env);
        free(env);
        env = &new_env[0];
    }

    bool has_prog = argc != optind;

    if (has_prog && exec_after_pr_caps)
        return print_err("print-caps=exec and program are mutually exclusive");

    if (!has_prog && (!pr_caps || no_save_session || no_pass_prompt))
    {
        print_err("No program provided");
        return show_usage(false);
    }

    if (keep_env && clear_env)
        return print_err("--keep-env and --clear-env are mutually exclusive");

    // Keep environment if user has no preference and UID/GID has not
    // been changed and the binary does not have SUID/SGID bit set.
    if (!keep_env && !clear_env && uid == -1 && gid == -1 && getuid() == geteuid() && getgid() == getegid())
        keep_env = true;

    if (has_prog && authenticate(!no_save_session, !no_pass_prompt))
        return 1;

    if (gid >= 0 && set_gid(gid))
        return 1;

    if ((groups != NULL || clear_groups) && set_groups(groups))
        return 1;

    if (caps != NULL && set_caps(caps, uid))
        return 1;

    if (uid >= 0 && set_uid(uid))
        return 1;

    if (caps && drop_permitted_caps(caps))
        return 1;

    if (pr_caps)
    {
        if (exec_after_pr_caps)
            print_out("\nBEFORE EXEC:\n============");

        print_caps(print_all_caps);

        char *TMP_FILE = "/tmp/print_privs-DELETE_ME";

        if (!exec_after_pr_caps)
            unlink(TMP_FILE);
        else
        {
            print_out("AFTER EXEC:\n===========");

            // We want to ignore the effect of setuid or setcap.
            if (copy_file(argv[0], TMP_FILE))
                return 1;

            if (chmod(TMP_FILE, S_IRWXU))
                return print_err_code("Failed to set mode on %s", TMP_FILE);

            char *new_argv[3];
            new_argv[0] = TMP_FILE;
            new_argv[1] = "--print-caps";
            new_argv[2] = 0;

            return exec_it(new_argv, keep_env, env);
        }
    }

    if (!has_prog)
        return 0;

    return exec_it(argv + optind, keep_env, env);
}
