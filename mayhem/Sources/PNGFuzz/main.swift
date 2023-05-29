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
var ctr = 0

@_cdecl("LLVMFuzzerTestOneInput")
public func PNGFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    ctr += 1

    do {
        let choice = fdp.ConsumeIntegralInRange(from: 0, to: 100)
        if (choice <= 99) {
            var stream = System.Blob(fdp.ConsumeRemainingData())
            let img = try PNG.Data.Rectangular.decompress(stream: &stream)
            img.unpack(as: PNG.RGBA<UInt8>.self)
        }
        else {
            var w: Int? = nil

            let pixels: Data = fdp.ConsumeRandomLengthData()
            if pixels.count == 0 {
                return -1
            }

            while w == nil || pixels.count % w! != 0 {
                w = fdp.ConsumeIntegralInRange(from: 1, to: pixels.count)
            }
            let h = pixels.count / w!
            let img = PNG.Data.Rectangular.init(packing: pixels.map {
                UInt8($0)
            },
                    size: (w!, h), layout: .init(format: .rgba8(palette: [], fill: nil)))
            var blob = System.Blob(Data())
            if fdp.ConsumeIntegralInRange(from: 1, to: 100) == 50 {
                try img.compress(stream: &blob, level: fdp.ConsumeIntegralInRange(from: 1, to: 10))
            }
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