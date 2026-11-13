// Arms a DeskID board to type the PIN digits after the next fingerprint match.
//
//     swift tools/deskid_arm.swift        # 10 seconds
//     swift tools/deskid_arm.swift 15     # the board caps this at 15
//     swift tools/deskid_arm.swift 0      # disarm
//
// The board types six keypad digits and Return into whatever has the
// keyboard. Put the cursor somewhere that is harmless, run this, then touch
// the ring. See "Touch only" in the README.

import Foundation
import IOKit.hid

let vendorID = 0xCAFE
let productID = 0xD15D

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let argument = CommandLine.arguments.dropFirst().first ?? "10"
guard let seconds = UInt8(argument) else {
    fail("usage: swift tools/deskid_arm.swift [seconds, 0 to 255]")
}

// Matching the vendor usage page keeps this away from the board's keyboard
// interface, which macOS guards with the Input Monitoring permission.
let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
IOHIDManagerSetDeviceMatching(manager, [
    kIOHIDVendorIDKey: vendorID,
    kIOHIDProductIDKey: productID,
    kIOHIDPrimaryUsagePageKey: 0xFF00,
    kIOHIDPrimaryUsageKey: 1,
] as CFDictionary)
guard let devices = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice>,
      let device = devices.first else {
    fail("No DeskID arming interface. Is the board plugged in and running a build with HID?")
}
guard IOHIDDeviceOpen(device, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else {
    fail("macOS refused to open the arming interface.")
}
defer { IOHIDDeviceClose(device, IOOptionBits(kIOHIDOptionsTypeNone)) }

var request = [UInt8](repeating: 0, count: 8)
request[0] = 0x01
request[1] = seconds
let sent = IOHIDDeviceSetReport(device, kIOHIDReportTypeFeature, 0, request, request.count)
guard sent == kIOReturnSuccess else {
    fail(String(format: "The board did not take the request (0x%08X).", sent))
}

// The board acts on a request between host messages, within 40 ms.
usleep(100_000)
var answer = [UInt8](repeating: 0, count: 8)
var length = answer.count
let read = IOHIDDeviceGetReport(device, kIOHIDReportTypeFeature, 0, &answer, &length)
guard read == kIOReturnSuccess, length >= 3 else {
    fail(String(format: "Sent, but the board did not report back (0x%08X).", read))
}
print("armed for \(answer[1]) s, \(answer[2]) emission(s) since power-up")
if seconds > 0 && answer[1] == 0 {
    print("The board ignored the request: this build was made without DESKID_ALLOW_AUTOTYPE.")
}
