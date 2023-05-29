// Created by Bailey Capuano for Mayhem integration
import Foundation

class FuzzedDataProvider {
    private var data_src: Data

    init(_ data: UnsafeRawPointer, _ count: Int) {
        data_src = Data(bytes: data, count: count)
    }

    private func RemainingBytes() -> Int {
        return data_src.count
    }

    private func CastToUInt64<T: FixedWidthInteger>(_ value: T) -> UInt64 {
        return UInt64(value.magnitude)
    }

    private func GetRangeForBitWidth<T: FixedWidthInteger>(of ty: T) -> (min: UInt64, max: UInt64)? {
        switch (ty) {
        case 8:
            return (UInt64(UInt8.min), UInt64(UInt8.max))
        case 16:
            return (UInt64(UInt16.min), UInt64(UInt16.max))
        case 32:
            return (UInt64(UInt32.min), UInt64(UInt32.max))
        case 64:
            return (UInt64(UInt64.min), UInt64(UInt64.max))
        default:
            return nil
        }
    }

    /**
     Consumes a number in the given range from the data source
     - Parameters:
       - min: Minimum value to consume
       - max: Maximum value to consume
     - Returns: A number in the range [min, max] or |min| if remaining bytes are empty
     */
    func ConsumeIntegralInRange<T: FixedWidthInteger>(from min: T, to max: T) -> T {
        if (min > max) {
            abort()
        }
        let range = CastToUInt64(max) - CastToUInt64(min)
        var result: UInt64 = 0
        var offset: UInt64 = 0

        while offset < MemoryLayout<T>.size * 8 && (range >> offset) > 0 && RemainingBytes() != 0 {
            let popped = data_src.popLast()!
            result = (result << 8) | UInt64(exactly: popped)!
            offset += 8
        }

        if (range != UInt64.max) {
            result = result % (range + 1)
        }
        return min + T(result)
    }

    func ConsumeIntegral<T: FixedWidthInteger & UnsignedInteger>() -> T {
        // Get the unsigned version of the type
        return ConsumeIntegralInRange(from: T.min, to: T.max)
    }

    func ConsumeBoolean() -> Bool {
        let v: UInt8 = ConsumeIntegral()
        return Bool(truncating: (v & 1) as NSNumber)
    }

    func ConsumeRandomLengthString() -> String {
        var result = "";
        var i = 0

        while i < RemainingBytes() {
            // Build character from uint8
            var next = Character(UnicodeScalar(data_src.popFirst()!))

            if (next == "\\" && RemainingBytes() != 0) {
                next = Character(UnicodeScalar(data_src.popFirst()!))
                if (next != "\\") {
                    break;
                }
            }
            result.append(next)
            i += 1
        }
        return result
    }

    func ConsumeRemainingString() -> String {
        let str = String(bytes: data_src, encoding: .utf8) ?? ""
        data_src.removeAll();
        return str;
    }

    func ConsumeRemainingData() -> Data {
        let data = data_src
        data_src.removeAll()
        return data
    }

    func ConsumeRandomLengthData() -> Data {
        let s = ConsumeRandomLengthString()
        return Data(s.utf8)
    }


    func PickValueInList<T>(from list: T) -> T.Element where T: Collection {
        return list[ConsumeIntegralInRange(from: 0, to: list.count - 1) as! T.Index]
    }
}
