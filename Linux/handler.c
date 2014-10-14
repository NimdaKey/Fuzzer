/* this program can execute and deal with the signals appropriately when child process crash !
** Refer to notSPIKEfile
*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <netinet/in.h>

#define ERR_CRASH 0
#define ERR_OK 1
int quiet = 1;
int c_pid=0;
int killsignum=SIGTERM;
int timeout = 2;

/* execute and deal with the signals appropriately
**	return: ERR_CRASH on a crash 
** 			ERR_OK on successful execute and terminate
*/

struct signal_description
{
	int sig;
	char *name;
	char *abbr;
} ;

struct signal_description signal_description[] = 
{
	{SIGHUP,"Hangup","SIGHUP"},
	{SIGINT,"Interrupt","SIGINT"},
	{SIGQUIT,
		"Quit","SIGQUIT"},
	{SIGILL,
		"Illegal instruction","SIGILL"},
	{SIGTRAP,
		"Trace trap","SIGTRAP"},
	{SIGABRT,
		"Abort","SIGABRT"},
	{SIGBUS,
		"BUS error","SIGBUS"},
	{SIGFPE,
		"Floating-point exception","SIGFPE"},
	{SIGKILL,
		"Kill","SIGKILL"},
	{SIGUSR1,
		"User-defined signal 1","SIGUSR1"},
	{SIGSEGV,
		"Segmentation violation","SIGSEGV"},
	{SIGUSR2,
		"User-defined signal 2","SIGUSR2"},
	{SIGPIPE,
		"Broken pipe","SIGPIPE"},
	{SIGALRM,
		"Alarm clock","SIGALRM"},
	{SIGTERM,
		"Termination","SIGTERM"},
	{SIGSTKFLT,
		"Stack fault","SIGSTKFLT"},
	{SIGCHLD,
		"Child status has changed","SIGCHLD"},
	{SIGCONT,
		"Continue","SIGCONT"},
	{SIGSTOP,
		"Stop","SIGSTOP"},
	{SIGTSTP,
		"Keyboard stop","SIGSTP"},
	{SIGTTIN,
		"Background read from tty","SIGTTIN"},
	{SIGTTOU,
		"Background write to tty","SIGTTOU"},
	{SIGURG,
		"Urgent condition on socket","SIGURG"},
	{SIGXCPU,
		"CPU limit exceeded","SIGXCPU"},
	{SIGXFSZ,
		"File size limit exceeded","SIGXFSZ"},
	{SIGVTALRM,
		"Virtual alarm clock","SIGVTALRM"},
	{SIGPROF,
		"Profiling alarm clock","SIGPROF"},
	{SIGWINCH,
		"Window size change","SIGWINCH"},
	{SIGIO,
		"I/O now possible","SIGIO"},
	{SIGPWR,
		"Power failure restart","SIGPWR"},
	{SIGSYS,"Bad system call","SIGSYS"},
	{32, "Realtime Signal #0",NULL},
	{-1,NULL}

};

/* 
** Function declaration
*/
int
F_execmon (char **argv, char **envp, time_t timeout, FILE *fBasefile);

char **
F_build_argv (char * buff,char * last);

void
usage(char *pname);

/* makes buff into an execve compatible array, makes last
** the last argument if not NULL
*/
char **
F_build_argv (char * buff,char * last)
{
	char *ptr;
	char **argp;
	char *string;
	u_int32_t ix = 1;
	u_int32_t elements;
	string = strdup (buff);
	ptr = string;

	while ( (ptr = strstr (ptr, " ")) )
	{
		ix++;
		while ( (*(ptr++) == ' ') )	 /* so multiple spaces is ok */
			if ( !(*ptr) )
				ix--; /* so trailing spaces with no more args is ok */
	}
	elements = ++ix;



	if ( !(argp = malloc (sizeof (char *) * (elements + 1 + (last!=NULL) ))) )
	{

		fprintf (stderr, "F_build_argv: malloc failed. fatal\n");
		exit (-1);
	}

	memset (argp, 0x0, sizeof (char *) * (elements + 1+(last!=NULL)));

	for ( ix = 0, ptr = string; ix < elements - 1; ix++ )
	{
		char *end;
		while ( *ptr && (*ptr == ' ') )
			ptr++;
		end = ptr;
		while ( *end && ((*end) != ' ') )
			end++;
		*end = 0x0;
		argp[ix] = strdup (ptr);
		ptr = end + 1;
	}
	if ( last )
	{
		if ( !quiet )
		{
			printf("Adding %s\n",last);
		}
		argp[ix++] = last;
	}
	argp[ix] = NULL;
	return(argp);
}

void main(int argc,char *argv[])
{
	char pBasefile[]="dump.dm";
	//char *args[]={"exception",NULL};
	int i = 0;
	int c;
	FILE *fp;
	char **argp;
	char *pCommand = NULL;
	
	while ( (c = getopt (argc, argv, "t:v")) != -1 )
	{
		switch ( c )
		{
			case 't':
				timeout = atoi (optarg);
				break;
			case 'v':
				quiet=0;
				break;
		}
	}


	if ( (argc - optind) != 1 )
	{
		printf("Missing arguments (%d).\n",argc - optind);
		usage (basename(argv[0]));
	}

	pCommand = strdup (argv[optind++]);
	
	printf("%s\n",pCommand);
	argp = F_build_argv(pCommand,NULL);
				
	F_execmon(argp,NULL,timeout,fp);
	return ;
	
}

char *
F_signum2ascii(int sig)
{
	int ix=0;
	while ( signal_description[ix].sig != -1 )
	{
		if ( signal_description[ix].sig == sig )
		{
			return(signal_description[ix].name);
		}
		ix++;
	}
	return("Unknown signal");
}

void
F_alarm_killer (int status)
{
	kill(c_pid,killsignum);
	return;
}

int
F_execmon (char **argv, char **envp, time_t timeout, FILE *fBasefile)
{
	pid_t pid;
	int status;
	struct user_regs_struct regs;
	char *pDumpfile;
	FILE *fp;
	fp=fBasefile;

	if ( !(pid = fork ()) )
	{ /* child */
		ptrace (PTRACE_TRACEME, 0, NULL, NULL);
/* XXX don't always want to close stdin/out/err XXX */
		close(fileno(stdin));
		close(fileno(stdout));
		close(fileno(stderr));
		
		if ( envp && argv )
			execve (argv[0], argv, envp);
		else if ( argv )
			execv (argv[0], argv);
		else
		{
			exit (4); /* XXX */
		}
	}
	else
	{ /* parent */
		
		
		c_pid = pid;
		signal (SIGALRM, F_alarm_killer);
monitor:
		alarm (timeout);
		waitpid (pid, &status, 0);
		alarm (0);
		if ( WIFEXITED (status) )
		{ /* program exited */
			if ( !quiet )
				printf ("Process %d exited with code %d\n", pid,
						WEXITSTATUS (status));
			return(ERR_OK);
		}
		else if ( WIFSIGNALED (status) )
		{ /* program ended because of a signal */
			if ( !quiet )
				printf ("Process %d terminated by unhandled signal %d\n", pid,
						WTERMSIG (status));
			return(ERR_OK);
		}
		else if ( WIFSTOPPED (status) )
		{ /* program stopped because of a signal */
			if ( !quiet )
				fprintf (stderr, "Process %d stopped due to signal %d (%s) \n",
						 pid,
						 WSTOPSIG (status), F_signum2ascii (WSTOPSIG (status)));
		}
		switch ( WSTOPSIG (status) )
		{ /* the following signals are usually all we care about */
			case SIGILL:
			case SIGBUS:
			case SIGSEGV:
			case SIGSYS:
			printf("Crash...\n");
/*
				pDumpfile = malloc(strlen(pOutfileProcess)+1+8+strlen("-dump.txt")+1);

				F_getregs (pid, &regs);
				sprintf(pDumpfile,"%s-%.8x-dump.txt",pBasefile,(unsigned)regs.eip);
				if ( !(fp = fopen(pDumpfile,"w")) )
				{
					perror("fopen");
					abort();
				}
				fprintf(fp,"TYPE %d: FUZZ %d: BYTE %d\n",type,fuzz,byte);
				F_printregs (fp,regs);
				F_libdis_print (fp,pid, 9, regs.eip);

				F_memdump (fp,pid, regs.esp, 128,"%esp");
				if ( (ptrace (PTRACE_CONT, pid, NULL,
							  (WSTOPSIG (status) == SIGTRAP) ? 0 : WSTOPSIG (status))) == -1 )
				{
					perror("ptrace");
				}

				ptrace(PTRACE_DETACH,pid,NULL,NULL);
				fclose(fp);
				*/
				return(ERR_CRASH);
		}
/* deliver the signal and keep tracing */
		if ( !quiet )
			fprintf (stderr, "Continuing...\n");
		if ( (ptrace (PTRACE_CONT, pid, NULL,
					  (WSTOPSIG (status) == SIGTRAP) ? 0 : WSTOPSIG (status))) == -1 )
		{
			perror("ptrace");
		}
		goto monitor;    
	}
	return(ERR_OK);
}

void usage(char *pname)
{
	printf ("%s\n",pname);
	printf ("\t%s [options] <command>\n",pname);
	printf ("\n\n");
	printf ("Required Options:\n\n");
	printf (" -t\tTimeout value (default=2)\n");\
	printf (" -v\tDisplay detail\n");
	printf ("\nCommand:\n\n");
	printf ("\tQuoted command to execute.\n");
	printf ("\n\n");
	printf ("Example:\n\n");
	printf
	("%s -t 3 -v  \"/usr/bin/ls -l\"\n\n",pname);
	exit (ERR_OK);
}
