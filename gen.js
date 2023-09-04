function onload() {
    var cookie = JSON.parse(document.cookie);
    document.getElementById("number_of_iterations").value = cookie["number_of_iterations"];
    for (var val in cookie) {
        if (val != "number_of_iterations") document.getElementById("adresses").innerHTML += "<option value=\"" + val + "\">";
    }

    var language = window.navigator.userLanguage || window.navigator.language;
    switch (language) {
        case "pl":
            document.getElementById("title").innerHTML = "Generator haseł";
            document.getElementById("legend_adress").innerHTML = "Adres strony";
            document.getElementById("legend__username").innerHTML = "Nazwa użytkownika";
            document.getElementById("legend_main_password").innerHTML = "Główne hasło";
            document.getElementById("legend_number_of_iterations").innerHTML = "Liczba iteracji";
            document.getElementById("number_of_iterations_tooltip").innerHTML = "Wielokrotne wykonywanie funkcji hashującej utrudnia złamanie hasła, ale zwiększa czas potrzebny na wygenerowanie go.";
            document.getElementById("legend_result").innerHTML = "Wygenerowane hasło";
            document.getElementById("button").value = "Generuj";
            document.getElementById("copy_to_clipboard_text").innerHTML = "Skopiuj do schowka";
        default:
    }
}
function suggest__usernames() {
    var cookie = JSON.parse(document.cookie);
    var adress = document.getElementById("adress").value;
    document.getElementById("_usernames").innerHTML = "";
    for (var val in cookie[adress]) {
        document.getElementById("_usernames").innerHTML += "<option value=\"" + cookie[adress][val] + "\">";
    }
}

function sha256(ascii) { //from https://github.com/geraintluff/sha256
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    };

    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j; // Used as a counter across the whole file
    var result = '';

    var words = [];
    var asciiBitLength = ascii[lengthProperty] * 8;

    //* caching results is optional - remove/add slash from front of this line to toggle
    // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
    // (we actually calculate the first 64, but extra values are just ignored)
    var hash = sha256.h = sha256.h || [];
    // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
    var k = sha256.k = sha256.k || [];
    var primeCounter = k[lengthProperty];
    /*/
    var hash = [], k = [];
    var primeCounter = 0;
    //*/

    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }

    ascii += '\x80'; // Append '1' bit (plus zero padding)
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00'; // More zero padding
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j >> 8) return; // ASCII check: only accept characters in range 0-255
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
    words[words[lengthProperty]] = (asciiBitLength)

    // process each chunk
    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
        var oldHash = hash;
        // This is now the "working hash", often labelled as variables a...g
        // (we have to truncate as well, otherwise extra entries at the end accumulate
        hash = hash.slice(0, 8);

        for (i = 0; i < 64; i++) {
            var i2 = i + j;
            // Expand the message into 64 words
            // Used below if
            var w15 = w[i - 15], w2 = w[i - 2];

            // Iterate
            var a = hash[0], e = hash[4];
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                + ((e & hash[5]) ^ ((~e) & hash[6])) // ch
                + k[i]
                // Expand the message schedule if needed
                + (w[i] = (i < 16) ? w[i] : (
                    w[i - 16]
                    + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) // s0
                    + w[i - 7]
                    + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10)) // s1
                ) | 0
                );
            // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])); // maj

            hash = [(temp1 + temp2) | 0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
            hash[4] = (hash[4] + temp1) | 0;
        }

        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
};
function generate_password() {
    var adress = document.getElementById("adress").value;
    var _username = document.getElementById("_username").value;
    var password = document.getElementById("password").value;
    var number_of_iterations = document.getElementById("number_of_iterations").value;
    var s = adress + _username + password;
    for (let i = 0; i < number_of_iterations; i++) {
        var h = sha256(s);
        s = h;
    }
    var result = "";
    for (let i = 0; i < h.length / 2; i++) {
        var n = (h.charCodeAt(2 * i) * 7 + h.charCodeAt(2 * i + 1) * 15) % (126 - 48);
        result += String.fromCharCode(n + 48);

    }
    document.getElementById("result").value = result;
    var exdays = 180;
    var exdate = new Date();
    exdate.setDate(exdate.getDate() + exdays);
    var cookie = JSON.parse(document.cookie);
    cookie["number_of_iterations"] = number_of_iterations;
    if (adress in cookie) {
        cookie[adress].push(_username);
    }
    else {
        cookie[adress] = [_username];
    }
    document.cookie = JSON.stringify(cookie) + (!exdays ? "" : "; expires=" + exdate.toUTCString());

}

function copy_password_to_clipboard() {
    var result = document.getElementById("result");
    result.select();
    result.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(result.value);
}