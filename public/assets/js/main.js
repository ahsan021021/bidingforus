!function(e, t) {
    "object" == typeof exports && "undefined" != typeof module ? module.exports = t() : "function" == typeof define && define.amd ? define(t) : (e = "undefined" != typeof globalThis ? globalThis : e || self).bootstrap = t()
}(this, function() {
    "use strict";
    var e,
        t;
    let n = "transitionend",
        r = e => {
            let t = e.getAttribute("data-bs-target");
            if (!t || "#" === t) {
                let n = e.getAttribute("href");
                if (!n || !n.includes("#") && !n.startsWith("."))
                    return null;
                n.includes("#") && !n.startsWith("#") && (n = `#${n.split("#")[1]}`),
                t = n && "#" !== n ? n.trim() : null
            }
            return t
        },
        l = e => {
            let t = r(e);
            return t ? document.querySelector(t) : null
        },
        a = e => {
            if (!e)
                return 0;
            let {transitionDuration: t, transitionDelay: n} = window.getComputedStyle(e),
                r = Number.parseFloat(t),
                l = Number.parseFloat(n);
            return r || l ? (t = t.split(",")[0], n = n.split(",")[0], (Number.parseFloat(t) + Number.parseFloat(n)) * 1e3) : 0
        },
        o = e => {
            e.dispatchEvent(new Event(n))
        },
        i = e => !!e && "object" == typeof e && (void 0 !== e.jquery && (e = e[0]), void 0 !== e.nodeType),
        s = e => i(e) ? e.jquery ? e[0] : e : "string" == typeof e && e.length > 0 ? document.querySelector(e) : null,
        u = e => {
            e.offsetHeight
        },
        c = () => {
            let {jQuery: e} = window;
            return e && !document.body.hasAttribute("data-bs-no-jquery") ? e : null
        },
        d = [],
        f = e => {
            "function" == typeof e && e()
        },
        g = (e, t, r=!0) => {
            if (!r) {
                f(e);
                return
            }
            let l = a(t) + 5,
                i = !1,
                s = ({target: r}) => {
                    r === t && (i = !0, t.removeEventListener(n, s), f(e))
                };
            t.addEventListener(n, s),
            setTimeout(() => {
                i || o(t)
            }, l)
        },
        h = /[^.]*(?=\..*)\.|.*/,
        p = /\..*/,
        m = {},
        v = 1,
        y = {
            mouseenter: "mouseover",
            mouseleave: "mouseout"
        },
        b = /^(mouseenter|mouseleave)/i,
        $ = new Set(["click", "dblclick", "mouseup", "mousedown", "contextmenu", "mousewheel", "DOMMouseScroll", "mouseover", "mouseout", "mousemove", "selectstart", "selectend", "keydown", "keypress", "keyup", "orientationchange", "touchstart", "touchmove", "touchend", "touchcancel", "pointerdown", "pointermove", "pointerup", "pointerleave", "pointercancel", "gesturestart", "gesturechange", "gestureend", "focus", "blur", "change", "reset", "select", "submit", "focusin", "focusout", "load", "unload", "beforeunload", "resize", "move", "DOMContentLoaded", "readystatechange", "error", "abort", "scroll"]);
    function E(e, t) {
        return t && `${t}::${v++}` || e.uidEvent || v++
    }
    function L(e) {
        return y[e = e.replace(p, "")] || e
    }
    let A = {
            on(e, t, n, r) {
                !function e(t, n, r, l, a) {
                    var o,
                        i,
                        s,
                        u,
                        c;
                    if ("string" != typeof n || !t)
                        return;
                    if (r || (r = l, l = null), b.test(n)) {
                        let d = e => function(t) {
                            if (!t.relatedTarget || t.relatedTarget !== t.delegateTarget && !t.delegateTarget.contains(t.relatedTarget))
                                return e.call(this, t)
                        };
                        l ? l = d(l) : r = d(r)
                    }
                    let [f, g, p] = function e(t, n, r) {
                            let l = "string" == typeof n,
                                a = L(t),
                                o = $.has(a);
                            return o || (a = t), [l, l ? r : n, a]
                        }(n, r, l),
                        v = function e(t) {
                            let n = E(t);
                            return t.uidEvent = n, m[n] = m[n] || {}, m[n]
                        }(t),
                        y = v[p] || (v[p] = {}),
                        w = function e(t, n, r=null) {
                            let l = Object.keys(t);
                            for (let a = 0, o = l.length; a < o; a++) {
                                let i = t[l[a]];
                                if (i.originalHandler === n && i.delegationSelector === r)
                                    return i
                            }
                            return null
                        }(y, g, f ? r : null);
                    if (w) {
                        w.oneOff = w.oneOff && a;
                        return
                    }
                    let N = E(g, n.replace(h, "")),
                        T = f ? (o = t, i = r, s = l, function e(t) {
                            let n = o.querySelectorAll(i);
                            for (let {target: r} = t; r && r !== this; r = r.parentNode)
                                for (let l = n.length; l--;)
                                    if (n[l] === r)
                                        return t.delegateTarget = r, e.oneOff && A.off(o, t.type, i, s), s.apply(r, [t]);
                            return null
                        }) : (u = t, c = r, function e(t) {
                            return t.delegateTarget = u, e.oneOff && A.off(u, t.type, c), c.apply(u, [t])
                        });
                    T.delegationSelector = f ? r : null,
                    T.originalHandler = g,
                    T.oneOff = a,
                    T.uidEvent = N,
                    y[N] = T,
                    t.addEventListener(p, T, f)
                }(e, t, n, r, !1)
            },
            trigger(e, t, n) {
                if ("string" != typeof t || !e)
                    return null;
                let r = c(),
                    l = L(t),
                    a = $.has(l),
                    o,
                    i = !0,
                    s = !0,
                    u = !1,
                    d = null;
                return t !== l && r && (o = r.Event(t, n), r(e).trigger(o), i = !o.isPropagationStopped(), s = !o.isImmediatePropagationStopped(), u = o.isDefaultPrevented()), a ? (d = document.createEvent("HTMLEvents")).initEvent(l, i, !0) : d = new CustomEvent(t, {
                    bubbles: i,
                    cancelable: !0
                }), void 0 !== n && Object.keys(n).forEach(e => {
                    Object.defineProperty(d, e, {
                        get: () => n[e]
                    })
                }), u && d.preventDefault(), s && e.dispatchEvent(d), d.defaultPrevented && void 0 !== o && o.preventDefault(), d
            }
        },
        w = new Map,
        N = {
            set(e, t, n) {
                w.has(e) || w.set(e, new Map);
                let r = w.get(e);
                if (!r.has(t) && 0 !== r.size) {
                    console.error(`Bootstrap doesn't allow more than one instance per element. Bound instance: ${Array.from(r.keys())[0]}.`);
                    return
                }
                r.set(t, n)
            },
            get: (e, t) => w.has(e) && w.get(e).get(t) || null
        };
    class T {
        constructor(e)
        {
            if (!(e = s(e)))
                return;
            this._element = e,
            N.set(this._element, this.constructor.DATA_KEY, this)
        }
        _queueCallback(e, t, n=!0)
        {
            g(e, t, n)
        }
        static getInstance(e)
        {
            return N.get(s(e), this.DATA_KEY)
        }
        static getOrCreateInstance(e, t={})
        {
            return this.getInstance(e) || new this(e, "object" == typeof t ? t : null)
        }
    }
    let O = {
            find: (e, t=document.documentElement) => [].concat(...Element.prototype.querySelectorAll.call(t, e)),
            children: (e, t) => [].concat(...e.children).filter(e => e.matches(t))
        },
        C = ".bs.tab",
        k = `hide${C}`,
        S = `hidden${C}`,
        D = `show${C}`,
        I = `shown${C}`,
        j = `click${C}.data-api`,
        q = "active",
        M = "fade",
        _ = "show",
        P = ".active",
        F = ":scope > li > .active";
    class H extends T {
        static get NAME()
        {
            return "tab"
        }
        show()
        {
            if (this._element.parentNode && this._element.parentNode.nodeType === Node.ELEMENT_NODE && this._element.classList.contains(q))
                return;
            let e,
                t = l(this._element),
                n = this._element.closest(".nav, .list-group");
            if (n) {
                let r = "UL" === n.nodeName || "OL" === n.nodeName ? F : P;
                e = (e = O.find(r, n))[e.length - 1]
            }
            let a = e ? A.trigger(e, k, {
                    relatedTarget: this._element
                }) : null,
                o = A.trigger(this._element, D, {
                    relatedTarget: e
                });
            if (o.defaultPrevented || null !== a && a.defaultPrevented)
                return;
            this._activate(this._element, n);
            let i = () => {
                A.trigger(e, S, {
                    relatedTarget: this._element
                }),
                A.trigger(this._element, I, {
                    relatedTarget: e
                })
            };
            t ? this._activate(t, t.parentNode, i) : i()
        }
        _activate(e, t, n)
        {
            let r = t && ("UL" === t.nodeName || "OL" === t.nodeName) ? O.find(F, t) : O.children(t, P),
                l = r[0],
                a = n && l && l.classList.contains(M),
                o = () => this._transitionComplete(e, l, n);
            l && a ? (l.classList.remove(_), this._queueCallback(o, e, !0)) : o()
        }
        _transitionComplete(e, t, n)
        {
            t && (t.classList.remove(q), "tab" === t.getAttribute("role") && t.setAttribute("aria-selected", !1)),
            e.classList.add(q),
            "tab" === e.getAttribute("role") && e.setAttribute("aria-selected", !0),
            u(e),
            e.classList.contains(M) && e.classList.add(_);
            let r = e.parentNode;
            r && "LI" === r.nodeName && (r = r.parentNode),
            n && n()
        }
        static jQueryInterface(e)
        {
            return this.each(function() {
                let t = H.getOrCreateInstance(this);
                if ("string" == typeof e) {
                    if (void 0 === t[e])
                        throw TypeError(`No method named "${e}"`);
                    t[e]()
                }
            })
        }
    }
    return A.on(document, j, '[data-bs-toggle="tab"], [data-bs-toggle="pill"], [data-bs-toggle="list"]', function(e) {
        ["A", "AREA"].includes(this.tagName) && e.preventDefault();
        let t = H.getOrCreateInstance(this);
        t.show()
    }), e = H, t = () => {
        let t = c();
        if (t) {
            let n = e.NAME,
                r = t.fn[n];
            t.fn[n] = e.jQueryInterface,
            t.fn[n].Constructor = e,
            t.fn[n].noConflict = () => (t.fn[n] = r, e.jQueryInterface)
        }
    }, "loading" === document.readyState ? (d.length || document.addEventListener("DOMContentLoaded", () => {
        d.forEach(e => e())
    }), d.push(t)) : t(), {
        Tab: H
    }
});
(function() {
    var t,
        e,
        n,
        i,
        r,
        o,
        s,
        a,
        u,
        l,
        d,
        h,
        p,
        c,
        m,
        f,
        g,
        v,
        $,
        y,
        b,
        M,
        _,
        T,
        E,
        w,
        x,
        S,
        L,
        D,
        F,
        A,
        C = [].slice;
    i = '<span class="odometer-digit"><span class="odometer-digit-spacer">8</span><span class="odometer-digit-inner">' + (c = '<span class="odometer-ribbon"><span class="odometer-ribbon-inner">' + (g = '<span class="odometer-value"></span>') + "</span></span>") + "</span></span>",
    s = '<span class="odometer-formatting-mark"></span>',
    n = "(,ddd).dd",
    a = /^\(?([^)]*)\)?(?:(.)(d+))?$/,
    o = 2e3,
    t = 20,
    l = 2,
    r = .5,
    d = 1e3 / (u = 30),
    e = 1e3 / t,
    m = "transitionend webkitTransitionEnd oTransitionEnd otransitionend MSTransitionEnd",
    f = null != (E = document.createElement("div").style).transition || null != E.webkitTransition || null != E.mozTransition || null != E.oTransition,
    _ = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame,
    h = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver,
    $ = function(t) {
        var e;
        return (e = document.createElement("div")).innerHTML = t, e.children[0]
    },
    M = function(t, e) {
        return t.className = t.className.replace(RegExp("(^| )" + e.split(" ").join("|") + "( |$)", "gi"), " ")
    },
    v = function(t, e) {
        return M(t, e), t.className += " " + e
    },
    w = function(t, e) {
        var n;
        return null != document.createEvent ? ((n = document.createEvent("HTMLEvents")).initEvent(e, !0, !0), t.dispatchEvent(n)) : void 0
    },
    b = function() {
        var t,
            e;
        return null != (t = null != (e = window.performance) && "function" == typeof e.now ? e.now() : void 0) ? t : +new Date
    },
    T = function(t, e) {
        return null == e && (e = 0), e ? (t *= Math.pow(10, e), t += .5, t = Math.floor(t), t /= Math.pow(10, e)) : Math.round(t)
    },
    x = function(t) {
        return 0 > t ? Math.ceil(t) : Math.floor(t)
    },
    y = function(t) {
        return t - T(t)
    },
    L = !1,
    (S = function() {
        var t,
            e,
            n,
            i,
            r;
        if (!L && null != window.jQuery) {
            for (L = !0, r = [], e = 0, n = (i = ["html", "text"]).length; n > e; e++)
                t = i[e],
                r.push(function(t) {
                    var e;
                    return e = window.jQuery.fn[t], window.jQuery.fn[t] = function(t) {
                        var n;
                        return null == t || null == (null != (n = this[0]) ? n.odometer : void 0) ? e.apply(this, arguments) : this[0].odometer.update(t)
                    }
                }(t));
            return r
        }
    })(),
    setTimeout(S, 0),
    (p = function() {
        function t(e) {
            var n,
                i,
                r,
                s,
                a,
                u,
                h,
                p,
                c,
                m,
                f = this;
            if (this.options = e, this.el = this.options.el, null != this.el.odometer)
                return this.el.odometer;
            for (i in this.el.odometer = this, p = t.options)
                s = p[i],
                null == this.options[i] && (this.options[i] = s);
            null == (a = this.options).duration && (a.duration = o),
            this.MAX_VALUES = this.options.duration / d / l | 0,
            this.resetFormat(),
            this.value = this.cleanValue(null != (c = this.options.value) ? c : ""),
            this.renderInside(),
            this.render();
            try {
                for (m = ["innerHTML", "innerText", "textContent"], u = 0, h = m.length; h > u; u++)
                    r = m[u],
                    null != this.el[r] && function(t) {
                        Object.defineProperty(f.el, t, {
                            get: function() {
                                var e;
                                return "innerHTML" === t ? f.inside.outerHTML : null != (e = f.inside.innerText) ? e : f.inside.textContent
                            },
                            set: function(t) {
                                return f.update(t)
                            }
                        })
                    }(r)
            } catch (g) {
                n = g,
                this.watchForMutations()
            }
        }
        return t.prototype.renderInside = function() {
            return this.inside = document.createElement("div"), this.inside.className = "odometer-inside", this.el.innerHTML = "", this.el.appendChild(this.inside)
        }, t.prototype.watchForMutations = function() {
            var t,
                e = this;
            if (null != h)
                try {
                    return null == this.observer && (this.observer = new h(function(t) {
                        var n;
                        return n = e.el.innerText, e.renderInside(), e.render(e.value), e.update(n)
                    })), this.watchMutations = !0, this.startWatchingMutations()
                } catch (n) {
                    t = n
                }
        }, t.prototype.startWatchingMutations = function() {
            return this.watchMutations ? this.observer.observe(this.el, {
                childList: !0
            }) : void 0
        }, t.prototype.stopWatchingMutations = function() {
            var t;
            return null != (t = this.observer) ? t.disconnect() : void 0
        }, t.prototype.cleanValue = function(t) {
            var e;
            return "string" == typeof t && (t = parseFloat(t = (t = (t = t.replace(null != (e = this.format.radix) ? e : ".", "<radix>")).replace(/[.,]/g, "")).replace("<radix>", "."), 10) || 0), T(t, this.format.precision)
        }, t.prototype.bindTransitionEnd = function() {
            var t,
                e,
                n,
                i,
                r,
                o,
                s = this;
            if (!this.transitionEndBound) {
                for (this.transitionEndBound = !0, e = !1, r = m.split(" "), o = [], n = 0, i = r.length; i > n; n++)
                    t = r[n],
                    o.push(this.el.addEventListener(t, function() {
                        return !!e || (e = !0, setTimeout(function() {
                                return s.render(), e = !1, w(s.el, "odometerdone")
                            }, 0), !0)
                    }, !1));
                return o
            }
        }, t.prototype.resetFormat = function() {
            var t,
                e,
                i,
                r,
                o,
                s,
                u,
                l;
            if ((t = null != (u = this.options.format) ? u : n) || (t = "d"), !(i = a.exec(t)))
                throw Error("Odometer: Unparsable digit format");
            return s = (l = i.slice(1, 4))[0], o = l[1], r = (null != (e = l[2]) ? e.length : void 0) || 0, this.format = {
                repeating: s,
                radix: o,
                precision: r
            }
        }, t.prototype.render = function(t) {
            var e,
                n,
                i,
                r,
                o,
                s,
                a;
            for (null == t && (t = this.value), this.stopWatchingMutations(), this.resetFormat(), this.inside.innerHTML = "", o = this.options.theme, e = this.el.className.split(" "), r = [], s = 0, a = e.length; a > s; s++)
                (n = e[s]).length && ((i = /^odometer-theme-(.+)$/.exec(n)) ? o = i[1] : /^odometer(-|$)/.test(n) || r.push(n));
            return r.push("odometer"), f || r.push("odometer-no-transitions"), o ? r.push("odometer-theme-" + o) : r.push("odometer-auto-theme"), this.el.className = r.join(" "), this.ribbons = {}, this.formatDigits(t), this.startWatchingMutations()
        }, t.prototype.formatDigits = function(t) {
            var e,
                n,
                i,
                r,
                o,
                s,
                a,
                u,
                l,
                d;
            if (this.digits = [], this.options.formatFunction)
                for (l = (i = this.options.formatFunction(t)).split("").reverse(), o = 0, a = l.length; a > o; o++)
                    (n = l[o]).match(/0-9/) ? ((e = this.renderDigit()).querySelector(".odometer-value").innerHTML = n, this.digits.push(e), this.insertDigit(e)) : this.addSpacer(n);
            else
                for (r = !this.format.precision || !y(t), d = t.toString().split("").reverse(), s = 0, u = d.length; u > s; s++)
                    "." === (e = d[s]) && (r = !0),
                    this.addDigit(e, r)
        }, t.prototype.update = function(t) {
            var e,
                n = this;
            return (e = (t = this.cleanValue(t)) - this.value) ? (M(this.el, "odometer-animating-up odometer-animating-down odometer-animating"), e > 0 ? v(this.el, "odometer-animating-up") : v(this.el, "odometer-animating-down"), this.stopWatchingMutations(), this.animate(t), this.startWatchingMutations(), setTimeout(function() {
                return n.el.offsetHeight, v(n.el, "odometer-animating")
            }, 0), this.value = t) : void 0
        }, t.prototype.renderDigit = function() {
            return $(i)
        }, t.prototype.insertDigit = function(t, e) {
            return null != e ? this.inside.insertBefore(t, e) : this.inside.children.length ? this.inside.insertBefore(t, this.inside.children[0]) : this.inside.appendChild(t)
        }, t.prototype.addSpacer = function(t, e, n) {
            var i;
            return (i = $(s)).innerHTML = t, n && v(i, n), this.insertDigit(i, e)
        }, t.prototype.addDigit = function(t, e) {
            var n,
                i,
                r,
                o;
            if (null == e && (e = !0), "-" === t)
                return this.addSpacer(t, null, "odometer-negation-mark");
            if ("." === t)
                return this.addSpacer(null != (o = this.format.radix) ? o : ".", null, "odometer-radix-mark");
            if (e)
                for (r = !1;;) {
                    if (!this.format.repeating.length) {
                        if (r)
                            throw Error("Bad odometer format without digits");
                        this.resetFormat(),
                        r = !0
                    }
                    if (n = this.format.repeating[this.format.repeating.length - 1], this.format.repeating = this.format.repeating.substring(0, this.format.repeating.length - 1), "d" === n)
                        break;
                    this.addSpacer(n)
                }
            return (i = this.renderDigit()).querySelector(".odometer-value").innerHTML = t, this.digits.push(i), this.insertDigit(i)
        }, t.prototype.animate = function(t) {
            return f && "count" !== this.options.animation ? this.animateSlide(t) : this.animateCount(t)
        }, t.prototype.animateCount = function(t) {
            var n,
                i,
                r,
                o,
                s,
                a = this;
            if (i = +t - this.value)
                return o = r = b(), n = this.value, (s = function() {
                    var u,
                        l,
                        d;
                    return b() - o > a.options.duration ? (a.value = t, a.render(), void w(a.el, "odometerdone")) : ((u = b() - r) > e && (r = b(), n += l = i * (d = u / a.options.duration), a.render(Math.round(n))), null != _ ? _(s) : setTimeout(s, e))
                })()
        }, t.prototype.getDigitCount = function() {
            var t,
                e,
                n,
                i,
                r,
                o;
            for (i = 1 <= arguments.length ? C.call(arguments, 0) : [], t = r = 0, o = i.length; o > r; t = ++r)
                n = i[t],
                i[t] = Math.abs(n);
            return Math.ceil(Math.log((e = Math.max.apply(Math, i)) + 1) / Math.log(10))
        }, t.prototype.getFractionalDigitCount = function() {
            var t,
                e,
                n,
                i,
                r,
                o,
                s;
            for (r = 1 <= arguments.length ? C.call(arguments, 0) : [], e = /^\-?\d*\.(\d*?)0*$/, t = o = 0, s = r.length; s > o; t = ++o)
                i = r[t],
                r[t] = i.toString(),
                null == (n = e.exec(r[t])) ? r[t] = 0 : r[t] = n[1].length;
            return Math.max.apply(Math, r)
        }, t.prototype.resetDigits = function() {
            return this.digits = [], this.ribbons = [], this.inside.innerHTML = "", this.resetFormat()
        }, t.prototype.animateSlide = function(t) {
            var e,
                n,
                i,
                o,
                s,
                a,
                u,
                l,
                d,
                h,
                p,
                c,
                m,
                f,
                g,
                $,
                y,
                b,
                M,
                _,
                T,
                E,
                w,
                S,
                L,
                D,
                F;
            if ($ = this.value, (l = this.getFractionalDigitCount($, t)) && (t *= Math.pow(10, l), $ *= Math.pow(10, l)), i = t - $) {
                for (this.bindTransitionEnd(), o = this.getDigitCount($, t), s = [], e = 0, p = M = 0; o >= 0 ? o > M : M > o; p = o >= 0 ? ++M : --M) {
                    if (y = x($ / Math.pow(10, o - p - 1)), Math.abs(a = (u = x(t / Math.pow(10, o - p - 1))) - y) > this.MAX_VALUES) {
                        for (h = [], c = a / (this.MAX_VALUES + this.MAX_VALUES * e * r), n = y; a > 0 && u > n || 0 > a && n > u;)
                            h.push(Math.round(n)),
                            n += c;
                        h[h.length - 1] !== u && h.push(u),
                        e++
                    } else
                        h = (function() {
                            F = [];
                            for (var t = y; u >= y ? u >= t : t >= u; u >= y ? t++ : t--)
                                F.push(t);
                            return F
                        }).apply(this);
                    for (p = _ = 0, E = h.length; E > _; p = ++_)
                        d = h[p],
                        h[p] = Math.abs(d % 10);
                    s.push(h)
                }
                for (this.resetDigits(), D = s.reverse(), p = T = 0, w = D.length; w > T; p = ++T)
                    for (h = D[p], this.digits[p] || this.addDigit(" ", p >= l), null == (b = this.ribbons)[p] && (b[p] = this.digits[p].querySelector(".odometer-ribbon-inner")), this.ribbons[p].innerHTML = "", 0 > i && (h = h.reverse()), m = L = 0, S = h.length; S > L; m = ++L)
                        d = h[m],
                        (g = document.createElement("div")).className = "odometer-value",
                        g.innerHTML = d,
                        this.ribbons[p].appendChild(g),
                        m === h.length - 1 && v(g, "odometer-last-value"),
                        0 === m && v(g, "odometer-first-value");
                return 0 > y && this.addDigit("-"), null != (f = this.inside.querySelector(".odometer-radix-mark")) && f.parent.removeChild(f), l ? this.addSpacer(this.format.radix, this.digits[l - 1], "odometer-radix-mark") : void 0
            }
        }, t
    }()).options = null != (F = window.odometerOptions) ? F : {},
    setTimeout(function() {
        var t,
            e,
            n,
            i,
            r;
        if (window.odometerOptions) {
            for (t in i = window.odometerOptions, r = [], i)
                e = i[t],
                r.push(null != (n = p.options)[t] ? (n = p.options)[t] : n[t] = e);
            return r
        }
    }, 0),
    p.init = function() {
        var t,
            e,
            n,
            i,
            r,
            o;
        if (null != document.querySelectorAll) {
            for (e = document.querySelectorAll(p.options.selector || ".odometer"), o = [], n = 0, i = e.length; i > n; n++)
                t = e[n],
                o.push(t.odometer = new p({
                    el: t,
                    value: null != (r = t.innerText) ? r : t.textContent
                }));
            return o
        }
    },
    null != (null != (A = document.documentElement) ? A.doScroll : void 0) && null != document.createEventObject ? (D = document.onreadystatechange, document.onreadystatechange = function() {
        return "complete" === document.readyState && !1 !== p.options.auto && p.init(), null != D ? D.apply(this, arguments) : void 0
    }) : document.addEventListener("DOMContentLoaded", function() {
        return !1 !== p.options.auto ? p.init() : void 0
    }, !1),
    "function" == typeof define && define.amd ? define([], function() {
        return p
    }) : "undefined" != typeof exports && null !== exports ? module.exports = p : window.Odometer = p
}).call(this);
!function(i) {
    "use strict";
    "function" == typeof define && define.amd ? define(["jquery"], i) : "undefined" != typeof exports ? module.exports = i(require("jquery")) : i(jQuery)
}(function(i) {
    "use strict";
    var t,
        e = window.Slick || {};
    (e = (t = 0, function e(s, o) {
        var n,
            l = this;
        l.defaults = {
            accessibility: !0,
            adaptiveHeight: !1,
            asNavFor: null,
            autoplay: !1,
            autoplaySpeed: 3e3,
            centerMode: !1,
            centerPadding: "50px",
            cssEase: "ease",
            customPaging: function(t, e) {
                return i('<button type="button" />').text(e + 1)
            },
            draggable: !0,
            easing: "linear",
            edgeFriction: .35,
            fade: !1,
            focusOnSelect: !1,
            focusOnChange: !1,
            infinite: !0,
            initialSlide: 0,
            mobileFirst: !1,
            pauseOnHover: !0,
            pauseOnFocus: !0,
            respondTo: "window",
            responsive: null,
            rows: 1,
            rtl: !1,
            slide: "",
            slidesPerRow: 1,
            slidesToShow: 1,
            slidesToScroll: 1,
            speed: 500,
            swipe: !0,
            swipeToSlide: !1,
            touchMove: !0,
            touchThreshold: 5,
            useCSS: !0,
            useTransform: !0,
            variableWidth: !1,
            vertical: !1,
            verticalSwiping: !1,
            waitForAnimate: !0,
            zIndex: 1e3
        },
        l.initials = {
            animating: !1,
            dragging: !1,
            autoPlayTimer: null,
            currentDirection: 0,
            currentLeft: null,
            currentSlide: 0,
            direction: 1,
            listWidth: null,
            listHeight: null,
            loadIndex: 0,
            scrolling: !1,
            slideCount: null,
            slideWidth: null,
            $slideTrack: null,
            $slides: null,
            sliding: !1,
            slideOffset: 0,
            swipeLeft: null,
            swiping: !1,
            $list: null,
            touchObject: {},
            transformsEnabled: !1,
            unslicked: !1
        },
        i.extend(l, l.initials),
        l.activeBreakpoint = null,
        l.animType = null,
        l.animProp = null,
        l.breakpoints = [],
        l.breakpointSettings = [],
        l.cssTransitions = !1,
        l.focussed = !1,
        l.interrupted = !1,
        l.hidden = "hidden",
        l.paused = !0,
        l.positionProp = null,
        l.respondTo = null,
        l.rowCount = 1,
        l.shouldClick = !0,
        l.$slider = i(s),
        l.$slidesCache = null,
        l.transformType = null,
        l.transitionType = null,
        l.visibilityChange = "visibilitychange",
        l.windowWidth = 0,
        l.windowTimer = null,
        n = i(s).data("slick") || {},
        l.options = i.extend({}, l.defaults, o, n),
        l.currentSlide = l.options.initialSlide,
        l.originalSettings = l.options,
        void 0 !== document.mozHidden ? (l.hidden = "mozHidden", l.visibilityChange = "mozvisibilitychange") : void 0 !== document.webkitHidden && (l.hidden = "webkitHidden", l.visibilityChange = "webkitvisibilitychange"),
        l.autoPlay = i.proxy(l.autoPlay, l),
        l.autoPlayClear = i.proxy(l.autoPlayClear, l),
        l.autoPlayIterator = i.proxy(l.autoPlayIterator, l),
        l.changeSlide = i.proxy(l.changeSlide, l),
        l.clickHandler = i.proxy(l.clickHandler, l),
        l.selectHandler = i.proxy(l.selectHandler, l),
        l.setPosition = i.proxy(l.setPosition, l),
        l.swipeHandler = i.proxy(l.swipeHandler, l),
        l.dragHandler = i.proxy(l.dragHandler, l),
        l.keyHandler = i.proxy(l.keyHandler, l),
        l.instanceUid = t++,
        l.htmlExpr = /^(?:\s*(<[\w\W]+>)[^>]*)$/,
        l.registerBreakpoints(),
        l.init(!0)
    })).prototype.activateADA = function() {
        this.$slideTrack.find(".slick-active").attr({
            "aria-hidden": "false"
        }).find("a, input, button, select").attr({
            tabindex: "0"
        })
    },
    e.prototype.animateHeight = function() {
        if (1 === this.options.slidesToShow && !0 === this.options.adaptiveHeight && !1 === this.options.vertical) {
            var i = this.$slides.eq(this.currentSlide).outerHeight(!0);
            this.$list.animate({
                height: i
            }, this.options.speed)
        }
    },
    e.prototype.animateSlide = function(t, e) {
        var s = {},
            o = this;
        o.animateHeight(),
        !0 === o.options.rtl && !1 === o.options.vertical && (t = -t),
        !1 === o.transformsEnabled ? !1 === o.options.vertical ? o.$slideTrack.animate({
            left: t
        }, o.options.speed, o.options.easing, e) : o.$slideTrack.animate({
            top: t
        }, o.options.speed, o.options.easing, e) : !1 === o.cssTransitions ? (!0 === o.options.rtl && (o.currentLeft = -o.currentLeft), i({
            animStart: o.currentLeft
        }).animate({
            animStart: t
        }, {
            duration: o.options.speed,
            easing: o.options.easing,
            step: function(i) {
                i = Math.ceil(i),
                !1 === o.options.vertical ? (s[o.animType] = "translate(" + i + "px, 0px)", o.$slideTrack.css(s)) : (s[o.animType] = "translate(0px," + i + "px)", o.$slideTrack.css(s))
            },
            complete: function() {
                e && e.call()
            }
        })) : (o.applyTransition(), t = Math.ceil(t), !1 === o.options.vertical ? s[o.animType] = "translate3d(" + t + "px, 0px, 0px)" : s[o.animType] = "translate3d(0px," + t + "px, 0px)", o.$slideTrack.css(s), e && setTimeout(function() {
            o.disableTransition(),
            e.call()
        }, o.options.speed))
    },
    e.prototype.getNavTarget = function() {
        var t = this.options.asNavFor;
        return t && null !== t && (t = i(t).not(this.$slider)), t
    },
    e.prototype.asNavFor = function(t) {
        var e = this.getNavTarget();
        null !== e && "object" == typeof e && e.each(function() {
            var e = i(this).slick("getSlick");
            e.unslicked || e.slideHandler(t, !0)
        })
    },
    e.prototype.applyTransition = function(i) {
        var t = this,
            e = {};
        !1 === t.options.fade ? e[t.transitionType] = t.transformType + " " + t.options.speed + "ms " + t.options.cssEase : e[t.transitionType] = "opacity " + t.options.speed + "ms " + t.options.cssEase,
        !1 === t.options.fade ? t.$slideTrack.css(e) : t.$slides.eq(i).css(e)
    },
    e.prototype.autoPlay = function() {
        var i = this;
        i.autoPlayClear(),
        i.slideCount > i.options.slidesToShow && (i.autoPlayTimer = setInterval(i.autoPlayIterator, i.options.autoplaySpeed))
    },
    e.prototype.autoPlayClear = function() {
        this.autoPlayTimer && clearInterval(this.autoPlayTimer)
    },
    e.prototype.autoPlayIterator = function() {
        var i = this,
            t = i.currentSlide + i.options.slidesToScroll;
        i.paused || i.interrupted || i.focussed || (!1 === i.options.infinite && (1 === i.direction && i.currentSlide + 1 === i.slideCount - 1 ? i.direction = 0 : 0 === i.direction && (t = i.currentSlide - i.options.slidesToScroll, i.currentSlide - 1 == 0 && (i.direction = 1))), i.slideHandler(t))
    },
    e.prototype.buildOut = function() {
        var t = this;
        t.$slides = t.$slider.children(t.options.slide + ":not(.slick-cloned)").addClass("slick-slide"),
        t.slideCount = t.$slides.length,
        t.$slides.each(function(t, e) {
            i(e).attr("data-slick-index", t).data("originalStyling", i(e).attr("style") || "")
        }),
        t.$slider.addClass("slick-slider"),
        t.$slideTrack = 0 === t.slideCount ? i('<div class="slick-track"/>').appendTo(t.$slider) : t.$slides.wrapAll('<div class="slick-track"/>').parent(),
        t.$list = t.$slideTrack.wrap('<div class="slick-list"/>').parent(),
        t.$slideTrack.css("opacity", 0),
        (!0 === t.options.centerMode || !0 === t.options.swipeToSlide) && (t.options.slidesToScroll = 1),
        i("img[data-lazy]", t.$slider).not("[src]").addClass("slick-loading"),
        t.setupInfinite(),
        t.setSlideClasses("number" == typeof t.currentSlide ? t.currentSlide : 0),
        !0 === t.options.draggable && t.$list.addClass("draggable")
    },
    e.prototype.buildRows = function() {
        var i,
            t,
            e,
            s,
            o,
            n,
            l;
        if (s = document.createDocumentFragment(), n = this.$slider.children(), this.options.rows > 0) {
            for (i = 0, l = this.options.slidesPerRow * this.options.rows, o = Math.ceil(n.length / l); i < o; i++) {
                var r = document.createElement("div");
                for (t = 0; t < this.options.rows; t++) {
                    var d = document.createElement("div");
                    for (e = 0; e < this.options.slidesPerRow; e++) {
                        var a = i * l + (t * this.options.slidesPerRow + e);
                        n.get(a) && d.appendChild(n.get(a))
                    }
                    r.appendChild(d)
                }
                s.appendChild(r)
            }
            this.$slider.empty().append(s),
            this.$slider.children().children().children().css({
                width: 100 / this.options.slidesPerRow + "%",
                display: "inline-block"
            })
        }
    },
    e.prototype.checkResponsive = function(t, e) {
        var s,
            o,
            n,
            l = this,
            r = !1,
            d = l.$slider.width(),
            a = window.innerWidth || i(window).width();
        if ("window" === l.respondTo ? n = a : "slider" === l.respondTo ? n = d : "min" === l.respondTo && (n = Math.min(a, d)), l.options.responsive && l.options.responsive.length && null !== l.options.responsive) {
            for (s in o = null, l.breakpoints)
                l.breakpoints.hasOwnProperty(s) && (!1 === l.originalSettings.mobileFirst ? n < l.breakpoints[s] && (o = l.breakpoints[s]) : n > l.breakpoints[s] && (o = l.breakpoints[s]));
            null !== o ? null !== l.activeBreakpoint ? (o !== l.activeBreakpoint || e) && (l.activeBreakpoint = o, "unslick" === l.breakpointSettings[o] ? l.unslick(o) : (l.options = i.extend({}, l.originalSettings, l.breakpointSettings[o]), !0 === t && (l.currentSlide = l.options.initialSlide), l.refresh(t)), r = o) : (l.activeBreakpoint = o, "unslick" === l.breakpointSettings[o] ? l.unslick(o) : (l.options = i.extend({}, l.originalSettings, l.breakpointSettings[o]), !0 === t && (l.currentSlide = l.options.initialSlide), l.refresh(t)), r = o) : null !== l.activeBreakpoint && (l.activeBreakpoint = null, l.options = l.originalSettings, !0 === t && (l.currentSlide = l.options.initialSlide), l.refresh(t), r = o),
            t || !1 === r || l.$slider.trigger("breakpoint", [l, r])
        }
    },
    e.prototype.changeSlide = function(t, e) {
        var s,
            o,
            n,
            l = i(t.currentTarget);
        switch (l.is("a") && t.preventDefault(), l.is("li") || (l = l.closest("li")), s = (n = this.slideCount % this.options.slidesToScroll != 0) ? 0 : (this.slideCount - this.currentSlide) % this.options.slidesToScroll, t.data.message) {
        case "previous":
            o = 0 === s ? this.options.slidesToScroll : this.options.slidesToShow - s,
            this.slideCount > this.options.slidesToShow && this.slideHandler(this.currentSlide - o, !1, e);
            break;
        case "next":
            o = 0 === s ? this.options.slidesToScroll : s,
            this.slideCount > this.options.slidesToShow && this.slideHandler(this.currentSlide + o, !1, e);
            break;
        case "index":
            var r = 0 === t.data.index ? 0 : t.data.index || l.index() * this.options.slidesToScroll;
            this.slideHandler(this.checkNavigable(r), !1, e),
            l.children().trigger("focus");
            break;
        default:
            return
        }
    },
    e.prototype.checkNavigable = function(i) {
        var t,
            e;
        if (t = this.getNavigableIndexes(), e = 0, i > t[t.length - 1])
            i = t[t.length - 1];
        else
            for (var s in t) {
                if (i < t[s]) {
                    i = e;
                    break
                }
                e = t[s]
            }
        return i
    },
    e.prototype.cleanUpEvents = function() {
        this.$slider.off("focus.slick blur.slick"),
        this.$list.off("touchstart.slick mousedown.slick", this.swipeHandler),
        this.$list.off("touchmove.slick mousemove.slick", this.swipeHandler),
        this.$list.off("touchend.slick mouseup.slick", this.swipeHandler),
        this.$list.off("touchcancel.slick mouseleave.slick", this.swipeHandler),
        this.$list.off("click.slick", this.clickHandler),
        i(document).off(this.visibilityChange, this.visibility),
        this.cleanUpSlideEvents(),
        !0 === this.options.accessibility && this.$list.off("keydown.slick", this.keyHandler),
        !0 === this.options.focusOnSelect && i(this.$slideTrack).children().off("click.slick", this.selectHandler),
        i(window).off("orientationchange.slick.slick-" + this.instanceUid, this.orientationChange),
        i(window).off("resize.slick.slick-" + this.instanceUid, this.resize),
        i("[draggable!=true]", this.$slideTrack).off("dragstart", this.preventDefault),
        i(window).off("load.slick.slick-" + this.instanceUid, this.setPosition)
    },
    e.prototype.cleanUpSlideEvents = function() {
        this.$list.off("mouseenter.slick", i.proxy(this.interrupt, this, !0)),
        this.$list.off("mouseleave.slick", i.proxy(this.interrupt, this, !1))
    },
    e.prototype.cleanUpRows = function() {
        var i;
        this.options.rows > 0 && ((i = this.$slides.children().children()).removeAttr("style"), this.$slider.empty().append(i))
    },
    e.prototype.clickHandler = function(i) {
        !1 === this.shouldClick && (i.stopImmediatePropagation(), i.stopPropagation(), i.preventDefault())
    },
    e.prototype.destroy = function(t) {
        var e = this;
        e.autoPlayClear(),
        e.touchObject = {},
        e.cleanUpEvents(),
        i(".slick-cloned", e.$slider).detach(),
        e.$slides && (e.$slides.removeClass("slick-slide slick-active slick-center slick-visible slick-current").removeAttr("aria-hidden").removeAttr("data-slick-index").each(function() {
            i(this).attr("style", i(this).data("originalStyling"))
        }), e.$slideTrack.children(this.options.slide).detach(), e.$slideTrack.detach(), e.$list.detach(), e.$slider.append(e.$slides)),
        e.cleanUpRows(),
        e.$slider.removeClass("slick-slider"),
        e.$slider.removeClass("slick-initialized"),
        e.unslicked = !0,
        t || e.$slider.trigger("destroy", [e])
    },
    e.prototype.disableTransition = function(i) {
        var t = this,
            e = {};
        e[t.transitionType] = "",
        !1 === t.options.fade ? t.$slideTrack.css(e) : t.$slides.eq(i).css(e)
    },
    e.prototype.fadeSlide = function(i, t) {
        var e = this;
        !1 === e.cssTransitions ? (e.$slides.eq(i).css({
            zIndex: e.options.zIndex
        }), e.$slides.eq(i).animate({
            opacity: 1
        }, e.options.speed, e.options.easing, t)) : (e.applyTransition(i), e.$slides.eq(i).css({
            opacity: 1,
            zIndex: e.options.zIndex
        }), t && setTimeout(function() {
            e.disableTransition(i),
            t.call()
        }, e.options.speed))
    },
    e.prototype.fadeSlideOut = function(i) {
        !1 === this.cssTransitions ? this.$slides.eq(i).animate({
            opacity: 0,
            zIndex: this.options.zIndex - 2
        }, this.options.speed, this.options.easing) : (this.applyTransition(i), this.$slides.eq(i).css({
            opacity: 0,
            zIndex: this.options.zIndex - 2
        }))
    },
    e.prototype.focusHandler = function() {
        var t = this;
        t.$slider.off("focus.slick blur.slick").on("focus.slick blur.slick", "*", function(e) {
            e.stopImmediatePropagation();
            var s = i(this);
            setTimeout(function() {
                t.options.pauseOnFocus && (t.focussed = s.is(":focus"), t.autoPlay())
            }, 0)
        })
    },
    e.prototype.getCurrent = e.prototype.slickCurrentSlide = function() {
        return this.currentSlide
    },
    e.prototype.getLeft = function(i) {
        var t,
            e,
            s,
            o,
            n = this,
            l = 0;
        return n.slideOffset = 0, e = n.$slides.first().outerHeight(!0), !0 === n.options.infinite ? (n.slideCount > n.options.slidesToShow && (n.slideOffset = -(n.slideWidth * n.options.slidesToShow * 1), o = -1, !0 === n.options.vertical && !0 === n.options.centerMode && (2 === n.options.slidesToShow ? o = -1.5 : 1 === n.options.slidesToShow && (o = -2)), l = e * n.options.slidesToShow * o), n.slideCount % n.options.slidesToScroll != 0 && i + n.options.slidesToScroll > n.slideCount && n.slideCount > n.options.slidesToShow && (i > n.slideCount ? (n.slideOffset = -((n.options.slidesToShow - (i - n.slideCount)) * n.slideWidth * 1), l = -((n.options.slidesToShow - (i - n.slideCount)) * e * 1)) : (n.slideOffset = -(n.slideCount % n.options.slidesToScroll * n.slideWidth * 1), l = -(n.slideCount % n.options.slidesToScroll * e * 1)))) : i + n.options.slidesToShow > n.slideCount && (n.slideOffset = (i + n.options.slidesToShow - n.slideCount) * n.slideWidth, l = (i + n.options.slidesToShow - n.slideCount) * e), n.slideCount <= n.options.slidesToShow && (n.slideOffset = 0, l = 0), !0 === n.options.centerMode && n.slideCount <= n.options.slidesToShow ? n.slideOffset = n.slideWidth * Math.floor(n.options.slidesToShow) / 2 - n.slideWidth * n.slideCount / 2 : !0 === n.options.centerMode && !0 === n.options.infinite ? n.slideOffset += n.slideWidth * Math.floor(n.options.slidesToShow / 2) - n.slideWidth : !0 === n.options.centerMode && (n.slideOffset = 0, n.slideOffset += n.slideWidth * Math.floor(n.options.slidesToShow / 2)), t = !1 === n.options.vertical ? -(i * n.slideWidth * 1) + n.slideOffset : -(i * e * 1) + l, !0 === n.options.variableWidth && (s = n.slideCount <= n.options.slidesToShow || !1 === n.options.infinite ? n.$slideTrack.children(".slick-slide").eq(i) : n.$slideTrack.children(".slick-slide").eq(i + n.options.slidesToShow), t = !0 === n.options.rtl ? s[0] ? -((n.$slideTrack.width() - s[0].offsetLeft - s.width()) * 1) : 0 : s[0] ? -1 * s[0].offsetLeft : 0, !0 === n.options.centerMode && (s = n.slideCount <= n.options.slidesToShow || !1 === n.options.infinite ? n.$slideTrack.children(".slick-slide").eq(i) : n.$slideTrack.children(".slick-slide").eq(i + n.options.slidesToShow + 1), t = !0 === n.options.rtl ? s[0] ? -((n.$slideTrack.width() - s[0].offsetLeft - s.width()) * 1) : 0 : s[0] ? -1 * s[0].offsetLeft : 0, t += (n.$list.width() - s.outerWidth()) / 2)), t
    },
    e.prototype.getOption = e.prototype.slickGetOption = function(i) {
        return this.options[i]
    },
    e.prototype.getNavigableIndexes = function() {
        var i,
            t = 0,
            e = 0,
            s = [];
        for (!1 === this.options.infinite ? i = this.slideCount : (t = -1 * this.options.slidesToScroll, e = -1 * this.options.slidesToScroll, i = 2 * this.slideCount); t < i;)
            s.push(t),
            t = e + this.options.slidesToScroll,
            e += this.options.slidesToScroll <= this.options.slidesToShow ? this.options.slidesToScroll : this.options.slidesToShow;
        return s
    },
    e.prototype.getSlick = function() {
        return this
    },
    e.prototype.getSlideCount = function() {
        var t,
            e,
            s,
            o = this;
        return (s = !0 === o.options.centerMode ? o.slideWidth * Math.floor(o.options.slidesToShow / 2) : 0, !0 === o.options.swipeToSlide) ? (o.$slideTrack.find(".slick-slide").each(function(t, n) {
            if (n.offsetLeft - s + i(n).outerWidth() / 2 > -1 * o.swipeLeft)
                return e = n, !1
        }), t = Math.abs(i(e).attr("data-slick-index") - o.currentSlide) || 1) : o.options.slidesToScroll
    },
    e.prototype.init = function(t) {
        var e = this;
        i(e.$slider).hasClass("slick-initialized") || (i(e.$slider).addClass("slick-initialized"), e.buildRows(), e.buildOut(), e.setProps(), e.startLoad(), e.loadSlider(), e.initializeEvents(), e.checkResponsive(!0), e.focusHandler()),
        t && e.$slider.trigger("init", [e]),
        !0 === e.options.accessibility && e.initADA(),
        e.options.autoplay && (e.paused = !1, e.autoPlay())
    },
    e.prototype.initADA = function() {
        var i = this;
        i.slideCount,
        i.options.slidesToShow,
        i.getNavigableIndexes().filter(function(t) {
            return t >= 0 && t < i.slideCount
        }),
        i.$slides.add(i.$slideTrack.find(".slick-cloned")).attr({
            "aria-hidden": "true",
            tabindex: "-1"
        }).find("a, input, button, select").attr({
            tabindex: "-1"
        });
        for (var t = i.currentSlide, e = t + i.options.slidesToShow; t < e; t++)
            i.options.focusOnChange ? i.$slides.eq(t).attr({
                tabindex: "0"
            }) : i.$slides.eq(t).removeAttr("tabindex");
        i.activateADA()
    },
    e.prototype.initSlideEvents = function() {
        this.options.pauseOnHover && (this.$list.on("mouseenter.slick", i.proxy(this.interrupt, this, !0)), this.$list.on("mouseleave.slick", i.proxy(this.interrupt, this, !1)))
    },
    e.prototype.initializeEvents = function() {
        this.initSlideEvents(),
        this.$list.on("touchstart.slick mousedown.slick", {
            action: "start"
        }, this.swipeHandler),
        this.$list.on("touchmove.slick mousemove.slick", {
            action: "move"
        }, this.swipeHandler),
        this.$list.on("touchend.slick mouseup.slick", {
            action: "end"
        }, this.swipeHandler),
        this.$list.on("touchcancel.slick mouseleave.slick", {
            action: "end"
        }, this.swipeHandler),
        this.$list.on("click.slick", this.clickHandler),
        i(document).on(this.visibilityChange, i.proxy(this.visibility, this)),
        !0 === this.options.accessibility && this.$list.on("keydown.slick", this.keyHandler),
        !0 === this.options.focusOnSelect && i(this.$slideTrack).children().on("click.slick", this.selectHandler),
        i(window).on("orientationchange.slick.slick-" + this.instanceUid, i.proxy(this.orientationChange, this)),
        i(window).on("resize.slick.slick-" + this.instanceUid, i.proxy(this.resize, this)),
        i("[draggable!=true]", this.$slideTrack).on("dragstart", this.preventDefault),
        i(window).on("load.slick.slick-" + this.instanceUid, this.setPosition),
        i(this.setPosition)
    },
    e.prototype.initUI = function() {},
    e.prototype.keyHandler = function(i) {
        i.target.tagName.match("TEXTAREA|INPUT|SELECT") || (37 === i.keyCode && !0 === this.options.accessibility ? this.changeSlide({
            data: {
                message: !0 === this.options.rtl ? "next" : "previous"
            }
        }) : 39 === i.keyCode && !0 === this.options.accessibility && this.changeSlide({
            data: {
                message: !0 === this.options.rtl ? "previous" : "next"
            }
        }))
    },
    e.prototype.loadSlider = function() {
        this.setPosition(),
        this.$slideTrack.css({
            opacity: 1
        }),
        this.$slider.removeClass("slick-loading"),
        this.initUI()
    },
    e.prototype.next = e.prototype.slickNext = function() {
        this.changeSlide({
            data: {
                message: "next"
            }
        })
    },
    e.prototype.orientationChange = function() {
        this.checkResponsive(),
        this.setPosition()
    },
    e.prototype.pause = e.prototype.slickPause = function() {
        var i = this;
        i.autoPlayClear(),
        i.paused = !0
    },
    e.prototype.play = e.prototype.slickPlay = function() {
        var i = this;
        i.autoPlay(),
        i.options.autoplay = !0,
        i.paused = !1,
        i.focussed = !1,
        i.interrupted = !1
    },
    e.prototype.postSlide = function(t) {
        var e = this;
        !e.unslicked && (e.$slider.trigger("afterChange", [e, t]), e.animating = !1, e.slideCount > e.options.slidesToShow && e.setPosition(), e.swipeLeft = null, e.options.autoplay && e.autoPlay(), !0 === e.options.accessibility && (e.initADA(), e.options.focusOnChange)) && i(e.$slides.get(e.currentSlide)).attr("tabindex", 0).focus()
    },
    e.prototype.prev = e.prototype.slickPrev = function() {
        this.changeSlide({
            data: {
                message: "previous"
            }
        })
    },
    e.prototype.preventDefault = function(i) {
        i.preventDefault()
    },
    e.prototype.refresh = function(t) {
        var e,
            s,
            o = this;
        s = o.slideCount - o.options.slidesToShow,
        !o.options.infinite && o.currentSlide > s && (o.currentSlide = s),
        o.slideCount <= o.options.slidesToShow && (o.currentSlide = 0),
        e = o.currentSlide,
        o.destroy(!0),
        i.extend(o, o.initials, {
            currentSlide: e
        }),
        o.init(),
        t || o.changeSlide({
            data: {
                message: "index",
                index: e
            }
        }, !1)
    },
    e.prototype.registerBreakpoints = function() {
        var t,
            e,
            s,
            o = this,
            n = o.options.responsive || null;
        if ("array" === i.type(n) && n.length) {
            for (t in o.respondTo = o.options.respondTo || "window", n)
                if (s = o.breakpoints.length - 1, n.hasOwnProperty(t)) {
                    for (e = n[t].breakpoint; s >= 0;)
                        o.breakpoints[s] && o.breakpoints[s] === e && o.breakpoints.splice(s, 1),
                        s--;
                    o.breakpoints.push(e),
                    o.breakpointSettings[e] = n[t].settings
                }
            o.breakpoints.sort(function(i, t) {
                return o.options.mobileFirst ? i - t : t - i
            })
        }
    },
    e.prototype.reinit = function() {
        var t = this;
        t.$slides = t.$slideTrack.children(t.options.slide).addClass("slick-slide"),
        t.slideCount = t.$slides.length,
        t.currentSlide >= t.slideCount && 0 !== t.currentSlide && (t.currentSlide = t.currentSlide - t.options.slidesToScroll),
        t.slideCount <= t.options.slidesToShow && (t.currentSlide = 0),
        t.registerBreakpoints(),
        t.setProps(),
        t.setupInfinite(),
        t.cleanUpSlideEvents(),
        t.initSlideEvents(),
        t.checkResponsive(!1, !0),
        !0 === t.options.focusOnSelect && i(t.$slideTrack).children().on("click.slick", t.selectHandler),
        t.setSlideClasses("number" == typeof t.currentSlide ? t.currentSlide : 0),
        t.setPosition(),
        t.focusHandler(),
        t.paused = !t.options.autoplay,
        t.autoPlay(),
        t.$slider.trigger("reInit", [t])
    },
    e.prototype.resize = function() {
        var t = this;
        i(window).width() !== t.windowWidth && (clearTimeout(t.windowDelay), t.windowDelay = window.setTimeout(function() {
            t.windowWidth = i(window).width(),
            t.checkResponsive(),
            t.unslicked || t.setPosition()
        }, 50))
    },
    e.prototype.setCSS = function(i) {
        var t,
            e,
            s = this,
            o = {};
        !0 === s.options.rtl && (i = -i),
        t = "left" == s.positionProp ? Math.ceil(i) + "px" : "0px",
        e = "top" == s.positionProp ? Math.ceil(i) + "px" : "0px",
        o[s.positionProp] = i,
        !1 === s.transformsEnabled ? s.$slideTrack.css(o) : (o = {}, !1 === s.cssTransitions ? (o[s.animType] = "translate(" + t + ", " + e + ")", s.$slideTrack.css(o)) : (o[s.animType] = "translate3d(" + t + ", " + e + ", 0px)", s.$slideTrack.css(o)))
    },
    e.prototype.setDimensions = function() {
        var i = this;
        !1 === i.options.vertical ? !0 === i.options.centerMode && i.$list.css({
            padding: "0px " + i.options.centerPadding
        }) : (i.$list.height(i.$slides.first().outerHeight(!0) * i.options.slidesToShow), !0 === i.options.centerMode && i.$list.css({
            padding: i.options.centerPadding + " 0px"
        })),
        i.listWidth = i.$list.width(),
        i.listHeight = i.$list.height(),
        !1 === i.options.vertical && !1 === i.options.variableWidth ? (i.slideWidth = Math.ceil(i.listWidth / i.options.slidesToShow), i.$slideTrack.width(Math.ceil(i.slideWidth * i.$slideTrack.children(".slick-slide").length))) : !0 === i.options.variableWidth ? i.$slideTrack.width(5e3 * i.slideCount) : (i.slideWidth = Math.ceil(i.listWidth), i.$slideTrack.height(Math.ceil(i.$slides.first().outerHeight(!0) * i.$slideTrack.children(".slick-slide").length)));
        var t = i.$slides.first().outerWidth(!0) - i.$slides.first().width();
        !1 === i.options.variableWidth && i.$slideTrack.children(".slick-slide").width(i.slideWidth - t)
    },
    e.prototype.setFade = function() {
        var t,
            e = this;
        e.$slides.each(function(s, o) {
            t = -(e.slideWidth * s * 1),
            !0 === e.options.rtl ? i(o).css({
                position: "relative",
                right: t,
                top: 0,
                zIndex: e.options.zIndex - 2,
                opacity: 0
            }) : i(o).css({
                position: "relative",
                left: t,
                top: 0,
                zIndex: e.options.zIndex - 2,
                opacity: 0
            })
        }),
        e.$slides.eq(e.currentSlide).css({
            zIndex: e.options.zIndex - 1,
            opacity: 1
        })
    },
    e.prototype.setHeight = function() {
        if (1 === this.options.slidesToShow && !0 === this.options.adaptiveHeight && !1 === this.options.vertical) {
            var i = this.$slides.eq(this.currentSlide).outerHeight(!0);
            this.$list.css("height", i)
        }
    },
    e.prototype.setOption = e.prototype.slickSetOption = function() {
        var t,
            e,
            s,
            o,
            n,
            l = this,
            r = !1;
        if ("object" === i.type(arguments[0]) ? (s = arguments[0], r = arguments[1], n = "multiple") : "string" === i.type(arguments[0]) && (s = arguments[0], o = arguments[1], r = arguments[2], "responsive" === arguments[0] && "array" === i.type(arguments[1]) ? n = "responsive" : void 0 !== arguments[1] && (n = "single")), "single" === n)
            l.options[s] = o;
        else if ("multiple" === n)
            i.each(s, function(i, t) {
                l.options[i] = t
            });
        else if ("responsive" === n)
            for (e in o)
                if ("array" !== i.type(l.options.responsive))
                    l.options.responsive = [o[e]];
                else {
                    for (t = l.options.responsive.length - 1; t >= 0;)
                        l.options.responsive[t].breakpoint === o[e].breakpoint && l.options.responsive.splice(t, 1),
                        t--;
                    l.options.responsive.push(o[e])
                }
        r && (l.unload(), l.reinit())
    },
    e.prototype.setPosition = function() {
        this.setDimensions(),
        this.setHeight(),
        !1 === this.options.fade ? this.setCSS(this.getLeft(this.currentSlide)) : this.setFade(),
        this.$slider.trigger("setPosition", [this])
    },
    e.prototype.setProps = function() {
        var i = this,
            t = document.body.style;
        i.positionProp = !0 === i.options.vertical ? "top" : "left",
        "top" === i.positionProp ? i.$slider.addClass("slick-vertical") : i.$slider.removeClass("slick-vertical"),
        (void 0 !== t.WebkitTransition || void 0 !== t.MozTransition || void 0 !== t.msTransition) && !0 === i.options.useCSS && (i.cssTransitions = !0),
        i.options.fade && ("number" == typeof i.options.zIndex ? i.options.zIndex < 3 && (i.options.zIndex = 3) : i.options.zIndex = i.defaults.zIndex),
        void 0 !== t.OTransform && (i.animType = "OTransform", i.transformType = "-o-transform", i.transitionType = "OTransition", void 0 === t.perspectiveProperty && void 0 === t.webkitPerspective && (i.animType = !1)),
        void 0 !== t.MozTransform && (i.animType = "MozTransform", i.transformType = "-moz-transform", i.transitionType = "MozTransition", void 0 === t.perspectiveProperty && void 0 === t.MozPerspective && (i.animType = !1)),
        void 0 !== t.webkitTransform && (i.animType = "webkitTransform", i.transformType = "-webkit-transform", i.transitionType = "webkitTransition", void 0 === t.perspectiveProperty && void 0 === t.webkitPerspective && (i.animType = !1)),
        void 0 !== t.msTransform && (i.animType = "msTransform", i.transformType = "-ms-transform", i.transitionType = "msTransition", void 0 === t.msTransform && (i.animType = !1)),
        void 0 !== t.transform && !1 !== i.animType && (i.animType = "transform", i.transformType = "transform", i.transitionType = "transition"),
        i.transformsEnabled = i.options.useTransform && null !== i.animType && !1 !== i.animType
    },
    e.prototype.setSlideClasses = function(i) {
        var t,
            e,
            s,
            o;
        if (e = this.$slider.find(".slick-slide").removeClass("slick-active slick-center slick-current").attr("aria-hidden", "true"), this.$slides.eq(i).addClass("slick-current"), !0 === this.options.centerMode) {
            var n = this.options.slidesToShow % 2 == 0 ? 1 : 0;
            t = Math.floor(this.options.slidesToShow / 2),
            !0 === this.options.infinite && (i >= t && i <= this.slideCount - 1 - t ? this.$slides.slice(i - t + n, i + t + 1).addClass("slick-active").attr("aria-hidden", "false") : (s = this.options.slidesToShow + i, e.slice(s - t + 1 + n, s + t + 2).addClass("slick-active").attr("aria-hidden", "false")), 0 === i ? e.eq(e.length - 1 - this.options.slidesToShow).addClass("slick-center") : i === this.slideCount - 1 && e.eq(this.options.slidesToShow).addClass("slick-center")),
            this.$slides.eq(i).addClass("slick-center")
        } else
            i >= 0 && i <= this.slideCount - this.options.slidesToShow ? this.$slides.slice(i, i + this.options.slidesToShow).addClass("slick-active").attr("aria-hidden", "false") : e.length <= this.options.slidesToShow ? e.addClass("slick-active").attr("aria-hidden", "false") : (o = this.slideCount % this.options.slidesToShow, s = !0 === this.options.infinite ? this.options.slidesToShow + i : i, this.options.slidesToShow == this.options.slidesToScroll && this.slideCount - i < this.options.slidesToShow ? e.slice(s - (this.options.slidesToShow - o), s + o).addClass("slick-active").attr("aria-hidden", "false") : e.slice(s, s + this.options.slidesToShow).addClass("slick-active").attr("aria-hidden", "false"))
    },
    e.prototype.setupInfinite = function() {
        var t,
            e,
            s,
            o = this;
        if (!0 === o.options.fade && (o.options.centerMode = !1), !0 === o.options.infinite && !1 === o.options.fade && (e = null, o.slideCount > o.options.slidesToShow)) {
            for (s = !0 === o.options.centerMode ? o.options.slidesToShow + 1 : o.options.slidesToShow, t = o.slideCount; t > o.slideCount - s; t -= 1)
                e = t - 1,
                i(o.$slides[e]).clone(!0).attr("id", "").attr("data-slick-index", e - o.slideCount).prependTo(o.$slideTrack).addClass("slick-cloned");
            for (t = 0; t < s + o.slideCount; t += 1)
                e = t,
                i(o.$slides[e]).clone(!0).attr("id", "").attr("data-slick-index", e + o.slideCount).appendTo(o.$slideTrack).addClass("slick-cloned");
            o.$slideTrack.find(".slick-cloned").find("[id]").each(function() {
                i(this).attr("id", "")
            })
        }
    },
    e.prototype.interrupt = function(i) {
        var t = this;
        i || t.autoPlay(),
        t.interrupted = i
    },
    e.prototype.selectHandler = function(t) {
        var e = parseInt((i(t.target).is(".slick-slide") ? i(t.target) : i(t.target).parents(".slick-slide")).attr("data-slick-index"));
        if (e || (e = 0), this.slideCount <= this.options.slidesToShow) {
            this.slideHandler(e, !1, !0);
            return
        }
        this.slideHandler(e)
    },
    e.prototype.slideHandler = function(i, t, e) {
        var s,
            o,
            n,
            l,
            r,
            d = null,
            a = this;
        if (t = t || !1, (!0 !== a.animating || !0 !== a.options.waitForAnimate) && (!0 !== a.options.fade || a.currentSlide !== i)) {
            if (!1 === t && a.asNavFor(i), s = i, d = a.getLeft(s), l = a.getLeft(a.currentSlide), a.currentLeft = null === a.swipeLeft ? l : a.swipeLeft, !1 === a.options.infinite && !1 === a.options.centerMode && (i < 0 || i > a.options.slidesToScroll) || !1 === a.options.infinite && !0 === a.options.centerMode && (i < 0 || i > a.slideCount - a.options.slidesToScroll)) {
                !1 === a.options.fade && (s = a.currentSlide, !0 !== e && a.slideCount > a.options.slidesToShow ? a.animateSlide(l, function() {
                    a.postSlide(s)
                }) : a.postSlide(s));
                return
            }
            if (a.options.autoplay && clearInterval(a.autoPlayTimer), o = s < 0 ? a.slideCount % a.options.slidesToScroll != 0 ? a.slideCount - a.slideCount % a.options.slidesToScroll : a.slideCount + s : s >= a.slideCount ? a.slideCount % a.options.slidesToScroll != 0 ? 0 : s - a.slideCount : s, a.animating = !0, a.$slider.trigger("beforeChange", [a, a.currentSlide, o]), n = a.currentSlide, a.currentSlide = o, a.setSlideClasses(a.currentSlide), a.options.asNavFor && (r = (r = a.getNavTarget()).slick("getSlick")).slideCount <= r.options.slidesToShow && r.setSlideClasses(a.currentSlide), !0 === a.options.fade) {
                !0 !== e ? (a.fadeSlideOut(n), a.fadeSlide(o, function() {
                    a.postSlide(o)
                })) : a.postSlide(o),
                a.animateHeight();
                return
            }
            !0 !== e && a.slideCount > a.options.slidesToShow ? a.animateSlide(d, function() {
                a.postSlide(o)
            }) : a.postSlide(o)
        }
    },
    e.prototype.startLoad = function() {
        this.$slider.addClass("slick-loading")
    },
    e.prototype.swipeDirection = function() {
        var i,
            t,
            e,
            s;
        return (i = this.touchObject.startX - this.touchObject.curX, (s = Math.round(180 * (e = Math.atan2(t = this.touchObject.startY - this.touchObject.curY, i)) / Math.PI)) < 0 && (s = 360 - Math.abs(s)), s <= 45 && s >= 0 || s <= 360 && s >= 315) ? !1 === this.options.rtl ? "left" : "right" : s >= 135 && s <= 225 ? !1 === this.options.rtl ? "right" : "left" : !0 === this.options.verticalSwiping ? s >= 35 && s <= 135 ? "down" : "up" : "vertical"
    },
    e.prototype.swipeEnd = function(i) {
        var t,
            e,
            s = this;
        if (s.dragging = !1, s.swiping = !1, s.scrolling)
            return s.scrolling = !1, !1;
        if (s.interrupted = !1, s.shouldClick = !(s.touchObject.swipeLength > 10), void 0 === s.touchObject.curX)
            return !1;
        if (!0 === s.touchObject.edgeHit && s.$slider.trigger("edge", [s, s.swipeDirection()]), s.touchObject.swipeLength >= s.touchObject.minSwipe) {
            switch (e = s.swipeDirection()) {
            case "left":
            case "down":
                t = s.options.swipeToSlide ? s.checkNavigable(s.currentSlide + s.getSlideCount()) : s.currentSlide + s.getSlideCount(),
                s.currentDirection = 0;
                break;
            case "right":
            case "up":
                t = s.options.swipeToSlide ? s.checkNavigable(s.currentSlide - s.getSlideCount()) : s.currentSlide - s.getSlideCount(),
                s.currentDirection = 1
            }
            "vertical" != e && (s.slideHandler(t), s.touchObject = {}, s.$slider.trigger("swipe", [s, e]))
        } else
            s.touchObject.startX !== s.touchObject.curX && (s.slideHandler(s.currentSlide), s.touchObject = {})
    },
    e.prototype.swipeHandler = function(i) {
        var t = this;
        if (!1 !== t.options.swipe && (!("ontouchend" in document) || !1 !== t.options.swipe)) {
            if (!1 !== t.options.draggable || -1 === i.type.indexOf("mouse"))
                switch (t.touchObject.fingerCount = i.originalEvent && void 0 !== i.originalEvent.touches ? i.originalEvent.touches.length : 1, t.touchObject.minSwipe = t.listWidth / t.options.touchThreshold, !0 === t.options.verticalSwiping && (t.touchObject.minSwipe = t.listHeight / t.options.touchThreshold), i.data.action) {
                case "start":
                    t.swipeStart(i);
                    break;
                case "move":
                    t.swipeMove(i);
                    break;
                case "end":
                    t.swipeEnd(i)
                }
        }
    },
    e.prototype.swipeMove = function(i) {
        var t,
            e,
            s,
            o,
            n,
            l,
            r = this;
        return n = void 0 !== i.originalEvent ? i.originalEvent.touches : null, !!r.dragging && !r.scrolling && (!n || 1 === n.length) && ((t = r.getLeft(r.currentSlide), r.touchObject.curX = void 0 !== n ? n[0].pageX : i.clientX, r.touchObject.curY = void 0 !== n ? n[0].pageY : i.clientY, r.touchObject.swipeLength = Math.round(Math.sqrt(Math.pow(r.touchObject.curX - r.touchObject.startX, 2))), l = Math.round(Math.sqrt(Math.pow(r.touchObject.curY - r.touchObject.startY, 2))), r.options.verticalSwiping || r.swiping || !(l > 4)) ? (!0 === r.options.verticalSwiping && (r.touchObject.swipeLength = l), e = r.swipeDirection(), void 0 !== i.originalEvent && r.touchObject.swipeLength > 4 && (r.swiping = !0, i.preventDefault()), o = (!1 === r.options.rtl ? 1 : -1) * (r.touchObject.curX > r.touchObject.startX ? 1 : -1), !0 === r.options.verticalSwiping && (o = r.touchObject.curY > r.touchObject.startY ? 1 : -1), s = r.touchObject.swipeLength, r.touchObject.edgeHit = !1, !1 === r.options.infinite && (0 === r.currentSlide && "right" === e || r.currentSlide >= 0 && "left" === e) && (s = r.touchObject.swipeLength * r.options.edgeFriction, r.touchObject.edgeHit = !0), !1 === r.options.vertical ? r.swipeLeft = t + s * o : r.swipeLeft = t + s * (r.$list.height() / r.listWidth) * o, !0 === r.options.verticalSwiping && (r.swipeLeft = t + s * o), !0 !== r.options.fade && !1 !== r.options.touchMove && (!0 === r.animating ? (r.swipeLeft = null, !1) : void r.setCSS(r.swipeLeft))) : (r.scrolling = !0, !1))
    },
    e.prototype.swipeStart = function(i) {
        var t,
            e = this;
        if (e.interrupted = !0, 1 !== e.touchObject.fingerCount || e.slideCount <= e.options.slidesToShow)
            return e.touchObject = {}, !1;
        void 0 !== i.originalEvent && void 0 !== i.originalEvent.touches && (t = i.originalEvent.touches[0]),
        e.touchObject.startX = e.touchObject.curX = void 0 !== t ? t.pageX : i.clientX,
        e.touchObject.startY = e.touchObject.curY = void 0 !== t ? t.pageY : i.clientY,
        e.dragging = !0
    },
    e.prototype.unload = function() {
        i(".slick-cloned", this.$slider).remove(),
        this.$slides.removeClass("slick-slide slick-active slick-visible slick-current").attr("aria-hidden", "true").css("width", "")
    },
    e.prototype.unslick = function(i) {
        this.$slider.trigger("unslick", [this, i]),
        this.destroy()
    },
    e.prototype.visibility = function() {
        var i = this;
        i.options.autoplay && (document[i.hidden] ? i.interrupted = !0 : i.interrupted = !1)
    },
    i.fn.slick = function() {
        var i,
            t,
            s = this,
            o = arguments[0],
            n = Array.prototype.slice.call(arguments, 1),
            l = s.length;
        for (i = 0; i < l; i++)
            if ("object" == typeof o || void 0 === o ? s[i].slick = new e(s[i], o) : t = s[i].slick[o].apply(s[i].slick, n), void 0 !== t)
                return t;
        return s
    }
});
!function(a) {
    a.fn.animatedHeadline = function(e) {
        function n(e) {
            var o = l(e);
            if (e.parents(".ah-headline").hasClass("type")) {
                var h = e.parent(".ah-words-wrapper");
                h.addClass("selected").removeClass("waiting"),
                setTimeout(function() {
                    h.removeClass("selected"),
                    e.removeClass("is-visible").addClass("is-hidden").children("i").removeClass("in").addClass("out")
                }, d.selectionDuration),
                setTimeout(function() {
                    s(o, d.typeLettersDelay)
                }, d.typeAnimationDelay)
            } else if (e.parents(".ah-headline").hasClass("letters")) {
                var p = e.children("i").length >= o.children("i").length;
                (function e(s, t, o, h) {
                    if (s.removeClass("in").addClass("out"), s.is(":last-child") ? o && setTimeout(function() {
                        n(l(t))
                    }, d.animationDelay) : setTimeout(function() {
                        e(s.next(), t, o, h)
                    }, h), s.is(":last-child") && a("html").hasClass("no-csstransitions")) {
                        var p = l(t);
                        r(t, p)
                    }
                })(e.find("i").eq(0), e, p, d.lettersDelay),
                t(o.find("i").eq(0), o, p, d.lettersDelay)
            } else
                e.parents(".ah-headline").hasClass("clip") ? e.parents(".ah-words-wrapper").animate({
                    width: "2px"
                }, d.revealDuration, function() {
                    r(e, o),
                    s(o)
                }) : e.parents(".ah-headline").hasClass("loading-bar") ? (e.parents(".ah-words-wrapper").removeClass("is-loading"), r(e, o), setTimeout(function() {
                    n(o)
                }, d.barAnimationDelay), setTimeout(function() {
                    e.parents(".ah-words-wrapper").addClass("is-loading")
                }, d.barWaiting)) : (r(e, o), setTimeout(function() {
                    n(o)
                }, d.animationDelay))
        }
        function s(a, e) {
            a.parents(".ah-headline").hasClass("type") ? (t(a.find("i").eq(0), a, !1, e), a.addClass("is-visible").removeClass("is-hidden")) : a.parents(".ah-headline").hasClass("clip") && a.parents(".ah-words-wrapper").animate({
                width: a.width() + 10
            }, d.revealDuration, function() {
                setTimeout(function() {
                    n(a)
                }, d.revealAnimationDelay)
            })
        }
        function t(a, e, s, l) {
            a.addClass("in").removeClass("out"),
            a.is(":last-child") ? (e.parents(".ah-headline").hasClass("type") && setTimeout(function() {
                e.parents(".ah-words-wrapper").addClass("waiting")
            }, 200), s || setTimeout(function() {
                n(e)
            }, d.animationDelay)) : setTimeout(function() {
                t(a.next(), e, s, l)
            }, l)
        }
        function l(a) {
            return a.is(":last-child") ? a.parent().children().eq(0) : a.next()
        }
        function r(a, e) {
            a.removeClass("is-visible").addClass("is-hidden"),
            e.removeClass("is-hidden").addClass("is-visible")
        }
        var d = a.extend({
                animationType: "rotate-1",
                animationDelay: 2500,
                barAnimationDelay: 3800,
                barWaiting: 800,
                lettersDelay: 50,
                typeLettersDelay: 150,
                selectionDuration: 500,
                typeAnimationDelay: 1300,
                revealDuration: 600,
                revealAnimationDelay: 1500
            }, e),
            o = d.animationDelay;
        this.each(function() {
            var e = a(this);
            if (d.animationType && ("type" == d.animationType || "rotate-2" == d.animationType || "rotate-3" == d.animationType || "scale" == d.animationType ? e.find(".ah-headline").addClass("letters " + d.animationType) : "clip" == d.animationType ? e.find(".ah-headline").addClass(d.animationType + " is-full-width") : e.find(".ah-headline").addClass(d.animationType)), function e(n) {
                n.each(function() {
                    var e = a(this),
                        n = e.text().split(""),
                        s = e.hasClass("is-visible");
                    for (i in n)
                        e.parents(".rotate-2").length > 0 && (n[i] = "<em>" + n[i] + "</em>"),
                        n[i] = s ? '<i class="in">' + n[i] + "</i>" : "<i>" + n[i] + "</i>";
                    var t = n.join("");
                    e.html(t).css("opacity", 1)
                })
            }(a(".ah-headline.letters").find("b")), e.hasClass("loading-bar"))
                o = d.barAnimationDelay,
                setTimeout(function() {
                    e.find(".ah-words-wrapper").addClass("is-loading")
                }, d.barWaiting);
            else if (e.hasClass("clip")) {
                var s = e.find(".ah-words-wrapper"),
                    t = s.width() + 10;
                s.css("width", t)
            } else if (!e.find(".ah-headline").hasClass("type")) {
                var l = e.find(".ah-words-wrapper b"),
                    r = 0;
                l.each(function() {
                    var e = a(this).width();
                    e > r && (r = e)
                }),
                e.find(".ah-words-wrapper").css("width", r)
            }
            setTimeout(function() {
                n(e.find(".is-visible").eq(0))
            }, o)
        })
    }
}(jQuery);
(function() {
    var t,
        e,
        n,
        i,
        o,
        r = function(t, e) {
            return function() {
                return t.apply(e, arguments)
            }
        },
        s = [].indexOf || function(t) {
            for (var e = 0, n = this.length; n > e; e++)
                if (e in this && this[e] === t)
                    return e;
            return -1
        };
    e = function() {
        function t() {}
        return t.prototype.extend = function(t, e) {
            var n,
                i;
            for (n in e)
                i = e[n],
                null == t[n] && (t[n] = i);
            return t
        }, t.prototype.isMobile = function(t) {
            return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(t)
        }, t.prototype.createEvent = function(t, e, n, i) {
            var o;
            return null == e && (e = !1), null == n && (n = !1), null == i && (i = null), null != document.createEvent ? (o = document.createEvent("CustomEvent")).initCustomEvent(t, e, n, i) : null != document.createEventObject ? (o = document.createEventObject()).eventType = t : o.eventName = t, o
        }, t.prototype.emitEvent = function(t, e) {
            return null != t.dispatchEvent ? t.dispatchEvent(e) : e in (null != t) ? t[e]() : "on" + e in (null != t) ? t["on" + e]() : void 0
        }, t.prototype.addEvent = function(t, e, n) {
            return null != t.addEventListener ? t.addEventListener(e, n, !1) : null != t.attachEvent ? t.attachEvent("on" + e, n) : t[e] = n
        }, t.prototype.removeEvent = function(t, e, n) {
            return null != t.removeEventListener ? t.removeEventListener(e, n, !1) : null != t.detachEvent ? t.detachEvent("on" + e, n) : delete t[e]
        }, t.prototype.innerHeight = function() {
            return "innerHeight" in window ? window.innerHeight : document.documentElement.clientHeight
        }, t
    }(),
    n = this.WeakMap || this.MozWeakMap || (n = function() {
        function t() {
            this.keys = [],
            this.values = []
        }
        return t.prototype.get = function(t) {
            var e,
                n,
                i,
                o,
                r;
            for (r = this.keys, e = i = 0, o = r.length; o > i; e = ++i)
                if ((n = r[e]) === t)
                    return this.values[e]
        }, t.prototype.set = function(t, e) {
            var n,
                i,
                o,
                r,
                s;
            for (s = this.keys, n = o = 0, r = s.length; r > o; n = ++o)
                if ((i = s[n]) === t)
                    return void (this.values[n] = e);
            return this.keys.push(t), this.values.push(e)
        }, t
    }()),
    t = this.MutationObserver || this.WebkitMutationObserver || this.MozMutationObserver || (t = function() {
        function t() {
            "undefined" != typeof console && null !== console && console.warn("MutationObserver is not supported by your browser."),
            "undefined" != typeof console && null !== console && console.warn("WOW.js cannot detect dom mutations, please call .sync() after loading new content.")
        }
        return t.notSupported = !0, t.prototype.observe = function() {}, t
    }()),
    i = this.getComputedStyle || function(t, e) {
        return this.getPropertyValue = function(e) {
            var n;
            return "float" === e && (e = "styleFloat"), o.test(e) && e.replace(o, function(t, e) {
                return e.toUpperCase()
            }), (null != (n = t.currentStyle) ? n[e] : void 0) || null
        }, this
    },
    o = /(\-([a-z]){1})/g,
    this.WOW = function() {
        function o(t) {
            null == t && (t = {}),
            this.scrollCallback = r(this.scrollCallback, this),
            this.scrollHandler = r(this.scrollHandler, this),
            this.resetAnimation = r(this.resetAnimation, this),
            this.start = r(this.start, this),
            this.scrolled = !0,
            this.config = this.util().extend(t, this.defaults),
            null != t.scrollContainer && (this.config.scrollContainer = document.querySelector(t.scrollContainer)),
            this.animationNameCache = new n,
            this.wowEvent = this.util().createEvent(this.config.boxClass)
        }
        return o.prototype.defaults = {
            boxClass: "wow",
            animateClass: "animated",
            offset: 0,
            mobile: !0,
            live: !0,
            callback: null,
            scrollContainer: null
        }, o.prototype.init = function() {
            var t;
            return this.element = window.document.documentElement, "interactive" === (t = document.readyState) || "complete" === t ? this.start() : this.util().addEvent(document, "DOMContentLoaded", this.start), this.finished = []
        }, o.prototype.start = function() {
            var e,
                n,
                i,
                o,
                r;
            if (this.stopped = !1, this.boxes = (function() {
                var t,
                    n,
                    i,
                    o;
                for (i = this.element.querySelectorAll("." + this.config.boxClass), o = [], t = 0, n = i.length; n > t; t++)
                    e = i[t],
                    o.push(e);
                return o
            }).call(this), this.all = (function() {
                var t,
                    n,
                    i,
                    o;
                for (i = this.boxes, o = [], t = 0, n = i.length; n > t; t++)
                    e = i[t],
                    o.push(e);
                return o
            }).call(this), this.boxes.length) {
                if (this.disabled())
                    this.resetStyle();
                else
                    for (o = this.boxes, n = 0, i = o.length; i > n; n++)
                        e = o[n],
                        this.applyStyle(e, !0)
            }
            return this.disabled() || (this.util().addEvent(this.config.scrollContainer || window, "scroll", this.scrollHandler), this.util().addEvent(window, "resize", this.scrollHandler), this.interval = setInterval(this.scrollCallback, 50)), this.config.live ? new t((r = this, function(t) {
                var e,
                    n,
                    i,
                    o,
                    s;
                for (s = [], e = 0, n = t.length; n > e; e++)
                    o = t[e],
                    s.push((function() {
                        var t,
                            e,
                            n,
                            r;
                        for (n = o.addedNodes || [], r = [], t = 0, e = n.length; e > t; t++)
                            i = n[t],
                            r.push(this.doSync(i));
                        return r
                    }).call(r));
                return s
            })).observe(document.body, {
                childList: !0,
                subtree: !0
            }) : void 0
        }, o.prototype.stop = function() {
            return this.stopped = !0, this.util().removeEvent(this.config.scrollContainer || window, "scroll", this.scrollHandler), this.util().removeEvent(window, "resize", this.scrollHandler), null != this.interval ? clearInterval(this.interval) : void 0
        }, o.prototype.sync = function(e) {
            return t.notSupported ? this.doSync(this.element) : void 0
        }, o.prototype.doSync = function(t) {
            var e,
                n,
                i,
                o,
                r;
            if (null == t && (t = this.element), 1 === t.nodeType) {
                for (o = (t = t.parentNode || t).querySelectorAll("." + this.config.boxClass), r = [], n = 0, i = o.length; i > n; n++)
                    e = o[n],
                    0 > s.call(this.all, e) ? (this.boxes.push(e), this.all.push(e), this.stopped || this.disabled() ? this.resetStyle() : this.applyStyle(e, !0), r.push(this.scrolled = !0)) : r.push(void 0);
                return r
            }
        }, o.prototype.show = function(t) {
            return this.applyStyle(t), t.className = t.className + " " + this.config.animateClass, null != this.config.callback && this.config.callback(t), this.util().emitEvent(t, this.wowEvent), this.util().addEvent(t, "animationend", this.resetAnimation), this.util().addEvent(t, "oanimationend", this.resetAnimation), this.util().addEvent(t, "webkitAnimationEnd", this.resetAnimation), this.util().addEvent(t, "MSAnimationEnd", this.resetAnimation), t
        }, o.prototype.applyStyle = function(t, e) {
            var n,
                i,
                o,
                r;
            return i = t.getAttribute("data-wow-duration"), n = t.getAttribute("data-wow-delay"), o = t.getAttribute("data-wow-iteration"), this.animate((r = this, function() {
                return r.customStyle(t, e, i, n, o)
            }))
        }, o.prototype.animate = "requestAnimationFrame" in window ? function(t) {
            return window.requestAnimationFrame(t)
        } : function(t) {
            return t()
        }, o.prototype.resetStyle = function() {
            var t,
                e,
                n,
                i,
                o;
            for (i = this.boxes, o = [], e = 0, n = i.length; n > e; e++)
                t = i[e],
                o.push(t.style.visibility = "visible");
            return o
        }, o.prototype.resetAnimation = function(t) {
            var e;
            return t.type.toLowerCase().indexOf("animationend") >= 0 ? (e = t.target || t.srcElement).className = e.className.replace(this.config.animateClass, "").trim() : void 0
        }, o.prototype.customStyle = function(t, e, n, i, o) {
            return e && this.cacheAnimationName(t), t.style.visibility = e ? "hidden" : "visible", n && this.vendorSet(t.style, {
                animationDuration: n
            }), i && this.vendorSet(t.style, {
                animationDelay: i
            }), o && this.vendorSet(t.style, {
                animationIterationCount: o
            }), this.vendorSet(t.style, {
                animationName: e ? "none" : this.cachedAnimationName(t)
            }), t
        }, o.prototype.vendors = ["moz", "webkit"], o.prototype.vendorSet = function(t, e) {
            var n,
                i,
                o,
                r;
            for (n in i = [], e)
                o = e[n],
                t["" + n] = o,
                i.push((function() {
                    var e,
                        i,
                        s,
                        l;
                    for (s = this.vendors, l = [], e = 0, i = s.length; i > e; e++)
                        r = s[e],
                        l.push(t["" + r + n.charAt(0).toUpperCase() + n.substr(1)] = o);
                    return l
                }).call(this));
            return i
        }, o.prototype.vendorCSS = function(t, e) {
            var n,
                o,
                r,
                s,
                l,
                a;
            for (s = (l = i(t)).getPropertyCSSValue(e), r = this.vendors, n = 0, o = r.length; o > n; n++)
                a = r[n],
                s = s || l.getPropertyCSSValue("-" + a + "-" + e);
            return s
        }, o.prototype.animationName = function(t) {
            var e;
            try {
                e = this.vendorCSS(t, "animation-name").cssText
            } catch (n) {
                e = i(t).getPropertyValue("animation-name")
            }
            return "none" === e ? "" : e
        }, o.prototype.cacheAnimationName = function(t) {
            return this.animationNameCache.set(t, this.animationName(t))
        }, o.prototype.cachedAnimationName = function(t) {
            return this.animationNameCache.get(t)
        }, o.prototype.scrollHandler = function() {
            return this.scrolled = !0
        }, o.prototype.scrollCallback = function() {
            var t;
            return !this.scrolled || (this.scrolled = !1, this.boxes = (function() {
                var e,
                    n,
                    i,
                    o;
                for (i = this.boxes, o = [], e = 0, n = i.length; n > e; e++)
                    (t = i[e]) && (this.isVisible(t) ? this.show(t) : o.push(t));
                return o
            }).call(this), this.boxes.length || this.config.live) ? void 0 : this.stop()
        }, o.prototype.offsetTop = function(t) {
            for (var e; void 0 === t.offsetTop;)
                t = t.parentNode;
            for (e = t.offsetTop; t = t.offsetParent;)
                e += t.offsetTop;
            return e
        }, o.prototype.isVisible = function(t) {
            var e,
                n,
                i,
                o,
                r;
            return n = t.getAttribute("data-wow-offset") || this.config.offset, o = (r = this.config.scrollContainer && this.config.scrollContainer.scrollTop || window.pageYOffset) + Math.min(this.element.clientHeight, this.util().innerHeight()) - n, e = (i = this.offsetTop(t)) + t.clientHeight, o >= i && e >= r
        }, o.prototype.util = function() {
            return null != this._util ? this._util : this._util = new e
        }, o.prototype.disabled = function() {
            return !this.config.mobile && this.util().isMobile(navigator.userAgent)
        }, o
    }()
}).call(this);
!function(e) {
    "use strict";
    if (e(window).on("load", function() {
        new WOW().init(),
        e("#form-contact-us").submit(function(t) {
            t.preventDefault();
            var i = e("#form-contact-us .btn");
            i.html(),
            e.ajax({
                type: "post",
                url: "https://bidman.co/send-message.php",
                data: e("#form-contact-us").serialize(),
                beforeSend: function() {
                    i.html("Sending..."),
                    i.prop("disabled", "disabled")
                }
            }).done(function(t) {
                "1" == t ? (i.html("Message sent"), e("#form-contact-us")[0].reset()) : i.html("Message not sent")
            }).fail(function() {
                i.html("Message not sent")
            }).always(function() {
                i.prop("disabled", ""),
                setTimeout(function() {
                    i.html("Send message")
                }, 2500)
            })
        })
    }), e(".mobile-menu").length) {
        var t = e(".menu-area .main-menu").html();
        e(".mobile-menu .menu-box .menu-outer").append(t),
        e(".mobile-nav-toggler").on("click", function() {
            e("body").addClass("mobile-menu-visible")
        }),
        e(".menu-backdrop, .mobile-menu .close-btn").on("click", function() {
            e("body").removeClass("mobile-menu-visible")
        })
    }
    var i = (e(".counter-item-wrap-three").length ? e(".counter-item-wrap-three").position().top : 0) - .8 * e(window).height();
    e(window).on("scroll", function() {
        var t = e(window).scrollTop();
        t < 245 ? (e("#sticky-header").removeClass("sticky-menu"), e(".scroll-top").removeClass("open"), e("#header-fixed-height").removeClass("active-height")) : (e("#sticky-header").addClass("sticky-menu"), e(".scroll-top").addClass("open"), e("#header-fixed-height").addClass("active-height")),
        e(".counter-item-wrap-three").length && t > i && e(".odometer").each(function() {
            var t = e(this).attr("data-count");
            e(this).html(t)
        })
    }),
    e(window).trigger("scroll"),
    e(".scroll-top").on("click", function() {
        window.scroll(0, 0)
    }),
    e(".ta-animated-headline") && e(".ta-animated-headline").animatedHeadline({
        animationType: "clip"
    }),
    e(".testimonial-active").slick({
        dots: !1,
        infinite: !0,
        speed: 1e3,
        autoplay: !0,
        arrows: !1,
        slidesToShow: 2,
        slidesToScroll: 1,
        centerMode: !0,
        centerPadding: "0",
        responsive: [{
            breakpoint: 1400,
            settings: {
                slidesToShow: 2,
                slidesToScroll: 1,
                infinite: !0,
                centerPadding: "0"
            }
        }, {
            breakpoint: 1200,
            settings: {
                slidesToShow: 1,
                slidesToScroll: 1,
                infinite: !0,
                centerPadding: "170px"
            }
        }, {
            breakpoint: 992,
            settings: {
                slidesToShow: 1,
                slidesToScroll: 1,
                centerPadding: "40px"
            }
        }, {
            breakpoint: 767,
            settings: {
                slidesToShow: 1,
                slidesToScroll: 1,
                arrows: !1,
                centerPadding: "20px"
            }
        }, {
            breakpoint: 575,
            settings: {
                slidesToShow: 1,
                slidesToScroll: 1,
                arrows: !1,
                centerPadding: "0px"
            }
        }, ]
    }),
    e(".pricing-tab-switcher, .tab-btn").on("click", function() {
        e(".pricing-tab-switcher, .tab-btn").toggleClass("active"),
        e(".pricing-tab").toggleClass("seleceted"),
        e(".pricing-price").toggleClass("change-subs-duration")
    })
}(jQuery);
