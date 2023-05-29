#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import PNG

extension System
{
    struct Blob
    {
        private(set)
        var data:[UInt8],
                position:Int
    }
}
extension System.Blob:PNG.Bytestream.Source, PNG.Bytestream.Destination
{
    init(_ data: Data)
    {
        self.data       = data.map { UInt8($0) }
        self.position   = data.startIndex
    }

    mutating
    func read(count:Int) -> [UInt8]?
    {
        guard self.position + count <= data.endIndex
        else
        {
            return nil
        }

        defer
        {
            self.position += count
        }

        return .init(self.data[self.position ..< self.position + count])
    }

    mutating
    func write(_ bytes:[UInt8]) -> Void?
    {
        self.data.append(contentsOf: bytes)
        return ()
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func PNGFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    do {
        let choice = fdp.ConsumeIntegralInRange(from: 0, to: 1)

        switch (choice) {
        case 0:
                var stream = System.Blob(fdp.ConsumeRemainingData())
                let img = try PNG.Data.Rectangular.decompress(stream: &stream)
                img.unpack(as: PNG.RGBA<UInt8>.self)
                return 0;
        case 1:
            var w: Int?  = nil

            let pixels: Data = fdp.ConsumeRandomLengthData()
            while w == nil || pixels.count % w! != 0 {
                w = fdp.ConsumeIntegralInRange(from: 1, to: pixels.count)
            }
            let h = pixels.count / w!
            let img = try PNG.Data.Rectangular.init(packing: pixels.map { UInt8($0) },
                    size: (w!, h), layout: .init(format: .rgba8(palette: [], fill: nil)))
            try img.compress(path: "/dev/null", level: fdp.ConsumeIntegralInRange(from: 0, to: 99))
        default:
            fatalError("Invalid fuzz choice")
        }
        return 0
    }
    catch is PNG.Error {
        return -1
    }
    catch let error {
        print(error.localizedDescription)
        print(type(of: error))
        exit(EXIT_FAILURE)
    }
}