#ifndef _API_H_
#define _API_H_

#include "user_config.h"

// Initialize API handlers
void api_init(void);

// Process HTTP request - returns true if handled as API call
bool api_handle_request(struct espconn *pespconn, char *data, unsigned short length);

#endif /* _API_H_ */
