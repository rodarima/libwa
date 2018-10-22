#include "wa.h"

int main()
{
	wa_t *wa = wa_init();
	wa_login(wa);

	wa_loop(wa);
	wa_free(wa);


	return 0;
}

