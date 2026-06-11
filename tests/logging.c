/*
 *  Copyright (C) 2026 Yubico AB - See COPYING
 */

#undef NDEBUG

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "logging.h"

/* Redirects stderr to a temporary file for the duration of fn(),
 * and returns whatever was written to it (NUL-terminated). */
static char *capture_stderr(void (*fn)(void)) {
  static char buf[4096];
  FILE *tmp;
  int saved;
  size_t n;

  tmp = tmpfile();
  assert(tmp != NULL);

  fflush(stderr);
  saved = dup(STDERR_FILENO);
  assert(saved != -1);
  assert(dup2(fileno(tmp), STDERR_FILENO) != -1);

  fn();

  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) != -1);
  close(saved);

  rewind(tmp);
  n = fread(buf, 1, sizeof(buf) - 1, tmp);
  buf[n] = '\0';
  fclose(tmp);

  return buf;
}

static void emit_debug(void) { LOG(LOG_DEBUG, "debug message"); }

static void emit_info(void) { LOG(LOG_INFO, "info message"); }

static void emit_notice(void) { LOG(LOG_NOTICE, "notice message"); }

static void emit_warning(void) { LOG(LOG_WARNING, "warning message"); }

static void emit_long_warning(void) {
  char big[3000];

  memset(big, 'A', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  LOG(LOG_WARNING, "%s", big);
}

static void test_default_level(void) {
  // The default level (LOG_INFO) hides "debug" but shows "info" and
  // higher, matching the pre-loglevel behavior of the legacy debug
  // bool.

  log_set_level(LOG_INFO);

  assert(strlen(capture_stderr(emit_debug)) == 0);

  assert(strstr(capture_stderr(emit_info), "info message") != NULL);
  assert(strstr(capture_stderr(emit_notice), "notice message") != NULL);
  assert(strstr(capture_stderr(emit_warning), "warning message") != NULL);
}

static void test_debug_level(void) {
  // loglevel=debug (and the legacy "debug" flag) show everything,
  // including "debug" level messages.

  log_set_level(LOG_DEBUG);

  assert(strstr(capture_stderr(emit_debug), "debug message") != NULL);
  assert(strstr(capture_stderr(emit_info), "info message") != NULL);
}

static void test_warning_level(void) {
  // loglevel=warning hides the per-authentication "info"/"notice"
  // audit records while still showing "warning" and above.

  log_set_level(LOG_WARNING);

  assert(strlen(capture_stderr(emit_info)) == 0);
  assert(strlen(capture_stderr(emit_notice)) == 0);
  assert(strstr(capture_stderr(emit_warning), "warning message") != NULL);
}

static void test_level_name(void) {
  char *out;

  log_set_level(LOG_DEBUG);

  out = capture_stderr(emit_debug);
  assert(strstr(out, "debug(pam_u2f)") != NULL);

  out = capture_stderr(emit_warning);
  assert(strstr(out, "warning(pam_u2f)") != NULL);
}

static void test_truncation(void) {
  char *out;

  log_set_level(LOG_DEBUG);

  out = capture_stderr(emit_long_warning);
  assert(strstr(out, "[truncated]") != NULL);
}

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  test_default_level();
  test_debug_level();
  test_warning_level();
  test_level_name();
  test_truncation();

  return 0;
}
