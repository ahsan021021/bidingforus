// 
// counert.js
// 

try {
    var setEndDate1 = "December 29, 2023 6:0:0";
    var setEndDate2 = "January 13, 2024 5:3:1";
    var setEndDate3 = "January 22, 2024 1:0:1";
    var setEndDate4 = "February 14, 2024 1:2:1";
    var setEndDate5 = "March 01, 2024 1:6:6";
    var setEndDate6 = "March 15, 2024 2:5:5";
    var setEndDate7 = "April 08, 2024 5:1:4";
    var setEndDate8 = "April 20, 2024 1:6:3";
    var setEndDate9 = "May 30, 2024 1:5:2";

    function startCountDownDate(dateVal) {
        var countDownDate = new Date(dateVal).getTime();
        return countDownDate;
    }

    function countDownTimer(start, targetDOM) {
        // Get todays date and time
        var now = new Date().getTime();

        // Find the distance between now and the count down date
        var distance = start - now;

        // Time calculations for days, hours, minutes and seconds
        var days = Math.floor(distance / (1000 * 60 * 60 * 24));
        var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        var seconds = Math.floor((distance % (1000 * 60)) / 1000);

        // add 0 at the beginning if days, hours, minutes, seconds values are less than 10
        days = (days < 10) ? "0" + days : days;
        hours = (hours < 10) ? "0" + hours : hours;
        minutes = (minutes < 10) ? "0" + minutes : minutes;
        seconds = (seconds < 10) ? "0" + seconds : seconds;

        // Output the result in an element with auction-item-x"
        document.querySelector("#" + targetDOM).textContent = days + " : " + hours + " : " + minutes + " : " + seconds;

        // If the count down is over, write some text 
        if (distance < 0) {
            // clearInterval();
            document.querySelector("#" + targetDOM).textContent = "00 : 00 : 00 : 00";
        }
    }

    var cdd1 = startCountDownDate(setEndDate1);
    var cdd2 = startCountDownDate(setEndDate2);
    var cdd3 = startCountDownDate(setEndDate3);
    var cdd4 = startCountDownDate(setEndDate4);
    var cdd5 = startCountDownDate(setEndDate5);
    var cdd6 = startCountDownDate(setEndDate6);
    var cdd7 = startCountDownDate(setEndDate7);
    var cdd8 = startCountDownDate(setEndDate8);
    var cdd9 = startCountDownDate(setEndDate9);

    if (document.getElementById("auction-item-1"))
        setInterval(function () { countDownTimer(cdd1, "auction-item-1"); }, 1000);
    if (document.getElementById("auction-item-2"))
        setInterval(function () { countDownTimer(cdd2, "auction-item-2"); }, 1000);
    if (document.getElementById("auction-item-3"))
        setInterval(function () { countDownTimer(cdd3, "auction-item-3"); }, 1000);
    if (document.getElementById("auction-item-4"))
        setInterval(function () { countDownTimer(cdd4, "auction-item-4"); }, 1000);
    if (document.getElementById("auction-item-5"))
        setInterval(function () { countDownTimer(cdd5, "auction-item-5"); }, 1000);
    if (document.getElementById("auction-item-6"))
        setInterval(function () { countDownTimer(cdd6, "auction-item-6"); }, 1000);
    if (document.getElementById("auction-item-7"))
        setInterval(function () { countDownTimer(cdd7, "auction-item-7"); }, 1000);
    if (document.getElementById("auction-item-8"))
        setInterval(function () { countDownTimer(cdd8, "auction-item-8"); }, 1000);
    if (document.getElementById("auction-item-9"))
        setInterval(function () { countDownTimer(cdd9, "auction-item-9"); }, 1000);

} catch (error) {

}

try {
    if (document.getElementById("days")) {
        // The data/time we want to countdown to
        var eventCountDown = new Date("December 25, 2023 16:37:52").getTime();

        // Run myfunc every second
        var myfunc = setInterval(function () {

            var now = new Date().getTime();
            var timeleft = eventCountDown - now;

            // Calculating the days, hours, minutes and seconds left
            var days = Math.floor(timeleft / (1000 * 60 * 60 * 24));
            var hours = Math.floor((timeleft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            var minutes = Math.floor((timeleft % (1000 * 60 * 60)) / (1000 * 60));
            var seconds = Math.floor((timeleft % (1000 * 60)) / 1000);

            // Result is output to the specific element
            document.getElementById("days").innerHTML = days + "<p class='count-head'>Days</p> "
            document.getElementById("hours").innerHTML = hours + "<p class='count-head'>Hours</p> "
            document.getElementById("mins").innerHTML = minutes + "<p class='count-head'>Mins</p> "
            document.getElementById("secs").innerHTML = seconds + "<p class='count-head'>Secs</p> "

            // Display the message when countdown is over
            if (timeleft < 0) {
                clearInterval(myfunc);
                document.getElementById("days").innerHTML = ""
                document.getElementById("hours").innerHTML = ""
                document.getElementById("mins").innerHTML = ""
                document.getElementById("secs").innerHTML = ""
                document.getElementById("end").innerHTML = "00:00:00:00";
            }
        }, 1000);
    }
} catch (err) {

}