# CAS authentication

## [frontend] on 401

* if the frontend encounters a 401 (not authorized) response, it loads the login URL (*not* via AJAX, but as a browser URL, so that the CAS login page can be rendered properly) 

Request:

	window.location.href = backend.url(`cas/login?target=${encodeURIComponent(window.location.href)}`);

## [backend] /cas/login

* register target URL (this will be the URL to redirect to after successful CAS login. This is the "deep link" into the desired place in your application)
* redirect to CAS login page, setting `service URL` to the URL `/cas`. This enables us to have *one* entry point for the redirects from the CAS server where e.g. 
	* the extraction of the service ticket should be handled
	* the redirection to the application target URL should be handled

=> redirect to:

	https://cas-server.server.com/login

## [CAS server] CAS login

* after CAS login, the CAS server redirect to the `service URL`, which is `/cas`

## [backend] GET /cas

* this backend route has 2 purposes:
	1. recognize the service ticket from the CAS server after successful CAS login
	2. end point for a single logout request from the CAS server


In this case (login), a service ticket is found in the URL (being called from the CAS server) and the backend:

1. validates the ticket: `https://cas-server.server.com/serviceValidate?ticket=ST-abcdef1234567890`
2. starts an application user session (the user is now "logged in" into the application)
2. redirects to the application target URL

## [frontend]

The target URL has been received, the application starts.

* request `/getUserId` synchronically to retrieve the session user name before the page is rendered.

## [backend] /session

This "cheap" request only returns the session data (e.g. user ID) from an active user session. There is no database access, just returning the user ID from the session to keep this request as fast as possible. If no user session exists, `null` is returned. The purpose of this route is to deliver all infos necessary to start rendering the page, but not more.

For example, the name of the logged in user can be retrieved later asynchronically by a separate request.

## [frontend]

If a user ID has been received, continue with rendering the page. Now the user is known, so the page can be rendered accurately, with all user-dependent page elements set up accordingly.

## [frontend] /users/current

Retrieve all data about current user, e.g. name (first and last name) asynchronically. This will be used to render the user's name on the page. Since this information is not necessary to be able to render the rest of the page, it can be done asynchronically. 
