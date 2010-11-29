
This OAuth 2.0 Provider java library is extension for OAuth java library(http://oauth.googlecode.com/svn/code/java/core/)
which was contributed by John Kristian, Praveen Alavilli and Dirk Balfanz.
This implementaion is based on draft-ietf-oauth-v2-10(http://tools.ietf.org/html/draft-ietf-oauth-v2-10).


Limitation:
-----------

#1 Only web server profile is supported.
#2 Access token lifetime is not examined.




How to build:
-------------

So far, you can build this with OAuth java library.
You have to download the OAuth java library source code tree from http://oauth.googlecode.com/svn/code/java/core/,
add directories for OAuth 2.0 Provider java library to the source code tree, and execute ant or maven to build.


(*)This library can work without OAuth java library. So I am going to make them possible to be built without that in near future.

Note:
-------------

JUnit test cases will be added to this github repository also.
