The protocol consists of messages with a tag and the content separed by a comma:

	<tag>,<content>

The server the replies using the same tag, and the reply:

	<tag>,<reply>

Some messages are not the response to any query, so the came with a random
looking tag.
