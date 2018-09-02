#include <stdio.h>
#include <stdlib.h>

char *generate_client_id();

int test_gen_id()
{
	char *id = generate_client_id();
	printf("%s\n", id);
	free(id);
	return 0;
}


int main()
{
	test_gen_id();
	return 0;
}
