/*
 * usage: frida -U Maps -l fake.js
 */
function fakeWithOrigin(location) {
  if (location.handle.isNull())
    return location;

  const CLLocationDegrees = (Process.pointerSize === 4) ? 'float' : 'double';
  const CLLocationCoordinate2D = [CLLocationDegrees, CLLocationDegrees];
  const CLLocationCoordinate2DMake = new NativeFunction(
    Module.findExportByName('CoreLocation', 'CLLocationCoordinate2DMake'),
    CLLocationCoordinate2D, [CLLocationDegrees, CLLocationDegrees]);

  // Las Cataratas del Iguazú, the other side of earth :)
  const fake = CLLocationCoordinate2DMake(-25.6952541, -54.4388549);
  const newLocation = ObjC.classes.CLLocation.alloc();
  newLocation['- initWithCoordinate:' +
    'altitude:' +
    'horizontalAccuracy:' +
    'verticalAccuracy:' +
    'course:' +
    'speed:' +
    'timestamp:'](
      fake,
      location.altitude(),
      location.horizontalAccuracy(),
      location.verticalAccuracy(),
      location.course(),
      location.speed(),
      location.timestamp()
    );

  return newLocation;
}

const hooked = {};
const callbacks = {
  '- locationManager:didUpdateToLocation:fromLocation:': function(args) {
    console.log('- locationManager:didUpdateToLocation:fromLocation:',
      new ObjC.Object(args[3]),
      new ObjC.Object(args[4]));

    const to = new ObjC.Object(args[3]);
    const from = new ObjC.Object(args[4]);

    args[3] = fakeWithOrigin(to);
    args[4] = fakeWithOrigin(from);
  },
  '- locationManager:didUpdateLocations:': function(args) {
    const newArray = ObjC.classes.NSMutableArray.alloc().init();
    const array = new ObjC.Object(args[3]);
    const count = array.count().valueOf();
    for (var i = 0; i !== count; i++) {
      const location = array.objectAtIndex_(i);
      const newLocation = fakeWithOrigin(location);
      newArray.addObject_(newLocation);
    }
    args[3] = newArray.copy();
  },
  '- locationManager:didUpdateHeading:': function(args) {
    console.log('- locationManager:didUpdateHeading:',
      new ObjC.Object(args[3]));
  }
};

[
  '- startUpdatingLocation',
  '- startUpdatingHeading', // heading is unavailable on macOS
  '- requestLocation'
].forEach(function(methodName) {
  if (!(methodName in ObjC.classes.CLLocationManager))
    return;

  Interceptor.attach(ObjC.classes.CLLocationManager[methodName].implementation, {
    onEnter: function(args) {
      const delegate = new ObjC.Object(args[0]).delegate();
      const className = delegate.$className;
      if (hooked[className]) return;
      const clazz = ObjC.classes[className];
      for (var sel in callbacks) {
        if (sel in clazz) {
          Interceptor.attach(clazz[sel].implementation, {
            onEnter: callbacks[sel]
          });
        }
      }

      hooked[className] = true;
    }
  });
});

