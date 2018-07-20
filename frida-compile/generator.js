function *gen() {
  yield 1;
  yield 2;
  yield 3;
}

for (let value of gen()) {
  console.log(value);
}