#include "time.h"

#include <iostream>
#include <iomanip>
#include <stdexcept>    // Needed for exception handling

using namespace std;


Time::Time(int h, int m, int s) {
   // Call setters to perform input validation
   setHour(h);
   setMinute(m);
   setSecond(s);
}

int Time::getHour() const {
   return hour;
}

void Time::setHour(int h) {  // with input validation
   if (h >= 0 && h <= 23) {
      hour = h;
   } else {
      throw invalid_argument("Invalid hour! Hour shall be 0-23.");
            // need <stdexcept>
   }
}

int Time::getMinute() const {
   return minute;
}

void Time::setMinute(int m) {
   if (m >= 0 && m <= 59) {
      minute = m;
   } else {
      throw invalid_argument("Invalid minute! Minute shall be 0-59.");
            // need <stdexcept>
   }
}

int Time::getSecond() const {
   return second;
}

void Time::setSecond(int s) {
   if (s >= 0 && s <= 59) {
      second = s;
   } else {
      throw invalid_argument("Invalid second! Second shall be 0-59.");
            // need <stdexcept>
   }
}

void Time::setTime(int h, int m, int s) {
   // Call setters to validate inputs
   setHour(h);
   setMinute(m);
   setSecond(s);
}

void Time::print() const {
   cout << setfill('0');
   cout << setw(2) << hour << ":" << setw(2) << minute << ":"
        << setw(2) << second << endl;
}
