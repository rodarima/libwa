## Design
The low level layer deals with websocket communications. The `ws.c` file
contains all the parts needed to connect to the WhatsApp websocket server, and
receive and send messages.

A message can be broken in fragments, which are not handled by the websocket
library.
