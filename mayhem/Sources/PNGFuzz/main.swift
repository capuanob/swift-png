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
        var stream = System.Blob(fdp.ConsumeRemainingData())
        try PNG.Data.Rectangular.decompress(stream: &stream)
        return 0;
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