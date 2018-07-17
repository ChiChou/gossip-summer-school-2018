// this example only supports macOS!
#include <CoreFoundation/CFRunLoop.h>

#include <iostream>
#include <sstream>
#include <string>

using namespace std;

enum Color { white, black, orange };

class Animal {
  int m_age;

public:
  Animal(int age) : m_age(age) {}

  virtual string kind() { return string("animal"); }

  bool grown() { return m_age > 1; }
};

class Cat : public Animal {
  int m_weight;

public:
  Cat(int age) : Animal(age), m_weight(5) {}

  Cat(int age, Color color) : Animal(age) {
    m_weight = 5;
    if (color == orange) {
      m_weight *= 2;
    }
  }

  virtual string kind() { return string(grown() ? "🐱" : "kitten"); }

  string toString() {
    std::ostringstream out("");
    out << "<Cat kind=" << kind() << " weight=" << m_weight << "kg"
        << ">";
    return out.str();
  }

  void talk() { cout << "meow" << endl; }

  void printDescription() { cout << toString() << endl; }
};

class Dog : public Animal {

public:
  Dog(int age) : Animal(age) {}

  virtual string kind() { return string(grown() ? "doggy" : "puppy"); }

  string toString() {
    std::ostringstream out("");
    out << "<Dog kind=" << kind() << " >";
    return out.str();
  }

  void talk() { cout << "ruff" << endl; }
};

int main(int argc, char *argv[]) {
  cout << "Cat: " << sizeof(Cat) << ", "
       << "Dog: " << sizeof(Dog) << endl;

  Cat cat(1, orange);
  cout << cat.toString() << endl;

  Dog dog(6);
  dog.talk();
  cout << dog.toString() << endl;

  Cat *oldCat = new Cat(10);
  oldCat->printDescription();
  cout << oldCat->toString() << endl;
  delete oldCat;

  // do not quit, so you can play in frida REPL
  CFRunLoopRun();
  return 0;
}
