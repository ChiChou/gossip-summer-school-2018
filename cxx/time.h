#ifndef TIME_H
#define TIME_H


class Time {
private:
   int hour;     // 0 - 23
   int minute;   // 0 - 59
   int second;   // 0 - 59

public:
   Time(int h = 0, int m = 0, int s = 0);
   int getHour() const;
   void setHour(int h);
   int getMinute() const;
   void setMinute(int m);
   int getSecond() const;
   void setSecond(int s);
   void setTime(int h, int m, int s);
   void print() const;
};

#endif // TIME_H
