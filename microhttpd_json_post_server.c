/*
 * gcc -g microhttpd_server.c -lmicrohttpd -ljson
 * curl -H "Content-Type: application/json" -X POST  --data '{"mpirun":"mpirun","action":"/home/guzheng/mpifileutils/install/bin/dcp","src":"/tmp/dir0/","dst":"/tmp/dir1/","options":"-v"}' http://127.0.0.1:8888
*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <stdint.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/param.h>   
#include <sys/types.h>   
#include <sys/stat.h>

#include <json-c/json.h>
#include <microhttpd.h>

#define PORT            8888
#define POSTBUFFERSIZE  32768
#define MAXNAMESIZE     20
#define MAXANSWERSIZE   512

#ifndef PATH_MAX
#define PATH_MAX	256
#endif

#define GET             0
#define POST            1

#define KEY_CONTENT_TYPE     "Content-Type"
#define KEY_CONTENT_JSON     "application/json"

#if 1
#define log_notice(...)  syslog(LOG_USER | LOG_NOTICE, __VA_ARGS__)
#define log_debug(...)   syslog(LOG_USER | LOG_DEBUG,  __VA_ARGS__)
#define log_error(...)   syslog(LOG_USER | LOG_ERR,    __VA_ARGS__)
#define log_info(...)   syslog(LOG_USER | LOG_INFO,    __VA_ARGS__)
#else
#define log_debug(...)   fprintf(stdout, __VA_ARGS__)
#define log_error(...)   fprintf(stderr, __VA_ARGS__)
#define log_notice(...)  fprintf(stdout, __VA_ARGS__)
#define log_info(...)	 fprintf(stdout, __VA_ARGS__)
#endif

struct MHD_Daemon *g_daemon;

struct connection_info_struct
{
	int connectiontype;
	char *answerstring;
	struct MHD_PostProcessor *postprocessor;
};

struct mpifileutil_args {
	char mpirun[PATH_MAX];
	char action[PATH_MAX];
	char src[PATH_MAX];
	char dst[PATH_MAX];
	char options[PATH_MAX];	
};

const char *askpage = "<html><body>\
                       mpifileutils http daemon<br>\
                       <form action=\"/namepost\" method=\"post\">\
                       <input name=\"name\" type=\"text\"\
                       <input type=\"submit\" value=\" Send \"></form>\
                       </body></html>";

const char *greetingpage =
	"<html><body><h1>Welcome, mpifileutils!</center></h1></body></html>";

const char *errorpage =
       "<html><body><h1>This doesn't seem to be right.</center></h1></body></html>";

#define HTTP_RESPONSE_400_ERRREQ		\
    "{\"status\":{\"code\":\"400\","		\
    "\"description\":\"Invalid json format\"}}"

#define HTTP_RESPONSE_404_NOTFOUND		\
    "{\"status\":{\"code\":\"404\","		\
    "\"description\":\"Resource Not Found\"}}"

#define HTTP_RESPONSE_201_CREATED		\
    "{\"status\":{\"code\":\"201\","		\
    "\"description\":\"Resource Created\"}}"

#define HTTP_RESPONSE_200_OK			\
    "{\"status\":{\"code\":\"200\","		\
    "\"description\":\"OK\"}}"

void json_print_value(json_object *obj);
void json_print_array(json_object *obj);
void json_print_object(json_object *obj);

void
json_print_array(json_object *obj)
{
	int i;
	int length;

	if (!obj)
		return;

	length = json_object_array_length(obj);

	for(i=0;i<length;i++) {
		json_object *val=json_object_array_get_idx(obj,i);

		json_print_value(val);
	}
}

void
json_print_object(json_object *obj)
{
	if (!obj)
		return;

	json_object_object_foreach(obj, key, val) {
		log_debug("%s => ",key);
		json_print_value(val);
	}
	log_debug("\n");
}

char *
json_get_value(json_object *obj, char *name)
{
	if (!obj)
		return;

	json_object_object_foreach(obj, key, val) {
		if (!strncmp(name, key, strlen(name))) {
			json_type type=json_object_get_type(val);

			if (type == json_type_string)
				return (char *)json_object_get_string(val);
			log_error("Invalid value format, expected is string!\n");
		}
	}
	return NULL;
}

void json_object_to_struct(json_object *obj, struct mpifileutil_args *args)
{
	char *value;

	memset(args, 0, sizeof(struct mpifileutil_args));
	value = json_get_value(obj, "mpirun");
	if (value && strlen(value))
		strncpy(args->mpirun, value, strlen(value));

	value = json_get_value(obj, "action");
	if (value && strlen(value))
		strncpy(args->action, value, strlen(value));

	value = json_get_value(obj, "src");
	if (value && strlen(value))
		strncpy(args->src, value, strlen(value));

	value = json_get_value(obj, "dst");
	if (value && strlen(value))
		strncpy(args->dst, value, strlen(value));

	value = json_get_value(obj, "options");
	if (value && strlen(value))
		strncpy(args->options, value, strlen(value));
}

int
excute_mpifileutils_action(struct mpifileutil_args *args)
{
	FILE *fp;
	char cmd[PATH_MAX] = {0};
	char buff[1024] = {0};
	int ret;

	sprintf(cmd, "%s %s %s %s %s 2>&1",
		args->mpirun, args->action, args->src,
		args->dst, args->options);

	log_debug("##Start to excute cmd:%s\n", cmd);

	fp = popen(cmd, "r");
	if (fp == NULL) {
		log_error("Failed to excute cmd:%s\n", cmd);
		return -1;
	}

	while (fgets(buff, sizeof(buff), fp) != NULL)
		log_debug("-%s-\n", buff);

	ret = fclose(fp);
	if(ret == -1) {
		log_error("Failed to close pipe\n");
		return -1;
	} else {
		log_debug("cmd:%s, %d, %d, %d\n", cmd, ret,
			  WIFEXITED(ret), WEXITSTATUS(ret));
	}

	return 0;
}

void
json_print_value(json_object *obj)
{
	if (!obj)
		return;

	json_type type=json_object_get_type(obj);
	if (type == json_type_boolean) {
		if(json_object_get_boolean(obj))
			log_debug("true");
		else
			log_debug("false");
	} else if (type == json_type_double) {
		log_debug("%lf",json_object_get_double(obj));
	} else if (type == json_type_int) {
		log_debug("%d",json_object_get_int(obj));
	} else if (type == json_type_string) {
		log_debug("%s",json_object_get_string(obj));
	} else if (type == json_type_object) {
		json_print_object(obj);
	} else if (type == json_type_array) {
		json_print_array(obj);
	} else {
		log_debug("ERROR");
	}
	log_debug(" ");
}

static int
check_json_content(void *cls, enum MHD_ValueKind kind, 
		    const char *key, const char *value)
{
	int *has_json = cls;

	if (strncmp(key, KEY_CONTENT_TYPE, strlen(KEY_CONTENT_TYPE)) == 0 &&
	    strncmp(value, KEY_CONTENT_JSON, strlen(KEY_CONTENT_JSON)) == 0)
		*has_json = 1;

	return MHD_YES;
}

static int
send_page(struct MHD_Connection *connection, const char *page)
{
	int ret;
	struct MHD_Response *response;

	response =
		MHD_create_response_from_buffer(strlen(page), (void *)page,
						MHD_RESPMEM_PERSISTENT);
	if (!response)
		return MHD_NO;

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}

static void
request_completed(void *cls, struct MHD_Connection *connection,
		  void **con_cls, enum MHD_RequestTerminationCode toe)
{
	struct connection_info_struct *con_info = *con_cls;

	if (con_info == NULL)
		return;

	if (con_info->answerstring)
		free(con_info->answerstring);

	free(con_info);
	*con_cls = NULL;
}

static int
answer_to_connection(void *cls, struct MHD_Connection *connection,
		     const char *url, const char *method,
		     const char *version, const char *upload_data,
		     size_t *upload_data_size, void **con_cls)
{
	const char * page = cls;
	int has_json = 0;

	MHD_get_connection_values(connection, MHD_HEADER_KIND,
                                  &check_json_content, &has_json);
	log_debug("######################\n");
	if (*con_cls == NULL) {
		struct connection_info_struct *con_info;

		con_info = malloc(sizeof(struct connection_info_struct));
		if (con_info == NULL)
			return MHD_NO;

		con_info->answerstring = NULL;

		if (!strcmp(method, "POST")) {
			con_info->connectiontype = POST;
		} else {
			con_info->connectiontype = GET;
		}

		*con_cls = (void *)con_info;

		return MHD_YES;
	}

	if (!strcmp(method, "GET")) {
		if (has_json) {
			log_error("Invalid form for GET!\n");
			return send_page(connection, errorpage);
		}

		return send_page(connection, askpage);
	}

	if (!strcmp (method, "POST")) {
		struct connection_info_struct *con_info = *con_cls;

		if (*upload_data_size) {
			con_info->answerstring = malloc(*upload_data_size + 1);
			strncpy(con_info->answerstring, upload_data, *upload_data_size);
			con_info->answerstring[*upload_data_size] = 0;
			*upload_data_size = 0;

			return MHD_YES;
		} else if (has_json) {
			struct mpifileutil_args args;
			int ret;

			memset(&args, 0, sizeof(struct mpifileutil_args));
			log_debug("Post data: %s\n", con_info->answerstring);
			json_object *obj = json_tokener_parse(con_info->answerstring);
			json_print_value(obj);
			json_object_to_struct(obj, &args);
			ret = excute_mpifileutils_action(&args);
			json_object_put(obj);
			if (!ret)
				return send_page(connection, HTTP_RESPONSE_200_OK);
		}
		log_error("Invalid post format:[%s]\n", con_info->answerstring);
		return send_page(connection, HTTP_RESPONSE_400_ERRREQ);
	}

	return send_page(connection, HTTP_RESPONSE_404_NOTFOUND);
}


static void
sig_kill_handler (int signum)
{
	log_debug("%s: killing daemon!\n", __func__);

	if (g_daemon)
		MHD_stop_daemon(g_daemon);

	closelog();

	exit(0);
}

static void
daemonize_this_process (void)
{
	pid_t pid;
	int fd;

	/* Fork parent and kill */
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* Set child as session leader */
	if (setsid() < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Fork keeping child as session leader */
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);
	chdir("/");

	for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--)
		close(fd);

	openlog("mpifileutils.microhttpd", LOG_PID, LOG_DAEMON);

	setlogmask(LOG_MASK(LOG_DEBUG)  | LOG_MASK(LOG_NOTICE) |
		   LOG_MASK(LOG_ERR));
}

/*
 * Start the webserver and listen to given port
 */

int
main(int argc, char **argv)
{
	struct MHD_Daemon *daemon;
	int ret;

	daemonize_this_process();

	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY|MHD_USE_DEBUG, PORT, NULL, NULL,
				  &answer_to_connection, (void *)greetingpage,
				  MHD_OPTION_NOTIFY_COMPLETED, request_completed,
				  NULL, MHD_OPTION_END);
	if (daemon == NULL) {
		log_error("Failed to start MHD daemon: %s", strerror(errno));
		ret = -1;
		goto out;
	}

	g_daemon = daemon;

	signal(SIGUSR1, sig_kill_handler);

	while (1)
		sleep(60);
out:
	return ret;
}
