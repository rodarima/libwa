#include "wa.h"

int main()
{
	struct wa *w = wa_init();
	wa_login(w);

	wa_loop(w);
	wa_free(w);


	return 0;
}

