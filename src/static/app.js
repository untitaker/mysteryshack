(function() {
    var elements = document.getElementsByClassName("user-agent");
    $(".user-agent").html(function() {
        var parser = new UAParser();
        parser.setUA($("").text());
        var ua = parser.getResult();

        var newHTML = "";
        newHTML +=
            '<img title="' +
            ua.browser.name +
            '" src="/static/ua/browser/' +
            encodeURI(ua.browser.name.toLowerCase()) +
            '.png" /> ';
        newHTML += '<img title="' +
            ua.os.name +
            '" src="/static/ua/os/' +
            encodeURI(ua.os.name.toLowerCase()) +
            '.png" />';
        return newHTML;
    });
})()
