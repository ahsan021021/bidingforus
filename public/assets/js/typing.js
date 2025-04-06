/*
Template Name: WebAi - AI Startup & Technology Landing Page HTML Template
Version: 1.0
Author: coderthemes
Email: support@coderthemes.com
File: typing.js
*/


function init() {
    (window.onload = (function () {
        function t(t, e, n) {
            (this.toRotate = e),
                (this.el = t),
                (this.loopNum = 0),
                (this.period = parseInt(n, 10) || 2e3),
                (this.txt = ""),
                this.tick(),
                (this.isDeleting = !1);
        }
        t.prototype.tick = function () {
            var t = this.loopNum % this.toRotate.length,
                t = this.toRotate[t],
                e =
                    (this.isDeleting
                        ? (this.txt = t.substring(0, this.txt.length - 1))
                        : (this.txt = t.substring(0, this.txt.length + 1)),
                        (this.el.innerHTML = '<span class="text-wrap">' + this.txt + "</span>"),
                        this),
                n = 200 - 100 * Math.random();
            this.isDeleting && (n /= 2),
                this.isDeleting || this.txt !== t
                    ? this.isDeleting &&
                    "" === this.txt &&
                    ((this.isDeleting = !1), this.loopNum++, (n = 500))
                    : ((n = this.period), (this.isDeleting = !0)),
                setTimeout(function () {
                    e.tick();
                }, n);
        };
        for (
            var e = document.getElementsByClassName("typewrite"), n = 0;
            n < e.length;
            n++
        ) {
            var i = e[n].getAttribute("data-type"),
                s = e[n].getAttribute("data-period");
            i && new t(e[n], JSON.parse(i), s);
        }
    })());
}
init();