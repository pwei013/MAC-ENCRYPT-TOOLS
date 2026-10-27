import AppKit
import Foundation

let folder = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let image = NSImage(size: NSSize(width: pixels, height: pixels))
        image.lockFocus()
        let p = CGFloat(pixels), inset = p * 0.06
        let shape = NSBezierPath(roundedRect: NSRect(x: inset, y: inset, width: p - inset * 2, height: p - inset * 2), xRadius: p * 0.20, yRadius: p * 0.20)
        NSGradient(starting: NSColor(calibratedRed: 0.28, green: 0.49, blue: 1, alpha: 1), ending: NSColor(calibratedRed: 0.15, green: 0.25, blue: 0.79, alpha: 1))!.draw(in: shape, angle: -60)
        let shield = NSBezierPath()
        shield.move(to: NSPoint(x: p * 0.5, y: p * 0.80))
        shield.line(to: NSPoint(x: p * 0.76, y: p * 0.70))
        shield.line(to: NSPoint(x: p * 0.73, y: p * 0.42))
        shield.curve(to: NSPoint(x: p * 0.5, y: p * 0.21), controlPoint1: NSPoint(x: p * 0.70, y: p * 0.32), controlPoint2: NSPoint(x: p * 0.58, y: p * 0.24))
        shield.curve(to: NSPoint(x: p * 0.27, y: p * 0.42), controlPoint1: NSPoint(x: p * 0.42, y: p * 0.24), controlPoint2: NSPoint(x: p * 0.30, y: p * 0.32))
        shield.line(to: NSPoint(x: p * 0.24, y: p * 0.70)); shield.close()
        NSColor.white.withAlphaComponent(0.95).setFill(); shield.fill()
        let ring = NSBezierPath(ovalIn: NSRect(x: p * 0.435, y: p * 0.50, width: p * 0.13, height: p * 0.13))
        NSColor(calibratedRed: 0.22, green: 0.38, blue: 0.91, alpha: 1).setFill(); ring.fill()
        let shaft = NSBezierPath(roundedRect: NSRect(x: p * 0.477, y: p * 0.37, width: p * 0.046, height: p * 0.19), xRadius: p * 0.02, yRadius: p * 0.02); shaft.fill()
        image.unlockFocus()
        let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
        let filename = "icon_\(size)x\(size)\(scale == 2 ? "@2x" : "").png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: folder.appendingPathComponent(filename))
    }
}
