## Protocol

The protocol consists of messages with a tag and the content separed by a comma:

	<tag>,<content>

The server then replies using the same tag, and the reply:

	<tag>,<reply>

Some messages are not the response to any query, so they came with a random
looking tag.

## Dispatcher

When the response of a query is requested, it is needed to wait until the
response arrives. In the meanwhile, several messages can arrive as well, with
different tags, belonging to other queries. A proper mechanism should be
designed to return only the correct response.

The websocket client runs in his own thread, and is continuously polling the
network socket for new data. In the meanwhile, several messages can arrive as
well, with different tags, belonging to other queries. A proper mechanism should
be designed to return only the correct response.

The websocket client runs in his own thread, and is continuously polling the
network socket for new data by the `lws_service()` call, using a large timeout.

When a new query arrives, the tag is added to a list with a `pthread_cond_t`, as
a pending message to be replied. The calling thread is then blocked, until the
response has been received. At this moment, the condition is signaled, and the
thread is unlocked, and the response is returned to the caller.

Unsolicited responses are handled differently.
