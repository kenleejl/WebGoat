function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
	// Credentials must never be embedded in downloadable client-side code.
	xhttp.send();
}
