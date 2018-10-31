/*
 * Copyright(c) 2018 Tim Rühsen
 * 
 * 
 */

#include <stdio.h>

#include <curl/curl.h>

int main(void)
{
	struct Curl_easy *easy = curl_easy_init();

	curl_easy_setopt(easy, CURLOPT_URL, "ftp://208.118.235.21/gnu/fe*");
	curl_easy_setopt(easy, CURLOPT_WILDCARDMATCH, 1);

	curl_easy_perform(easy);

	curl_easy_cleanup(easy);

	return 0;
}
