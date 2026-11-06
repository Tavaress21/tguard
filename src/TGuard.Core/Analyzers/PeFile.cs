using System.Buffers.Binary;
using System.Text;

namespace TGuard.Core.Analyzers;

public sealed class PeFile
{
    public sealed record Section(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize, uint Characteristics)
    {
        public bool Executable => (Characteristics & 0x20000000) != 0;
        public bool Writable => (Characteristics & 0x80000000) != 0;
    }

    public bool Is64 { get; private set; }
    public bool IsDll { get; private set; }
    public ushort Machine { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public List<Section> Sections { get; } = new();
    public List<(string Dll, string Function)> Imports { get; } = new();
    public (uint Rva, uint Size) SecurityDirectory { get; private set; }
    public long OverlaySize { get; private set; }
    public bool IsDotNet { get; private set; }

    private readonly byte[] _d;

    private PeFile(byte[] data) => _d = data;

    public static PeFile? TryParse(byte[] data, out string? error)
    {
        error = null;
        try
        {
            var pe = new PeFile(data);
            pe.Parse();
            return pe;
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or FormatException)
        {
            error = ex.Message;
            return null;
        }
    }

    private ushort U16(long o) => BinaryPrimitives.ReadUInt16LittleEndian(_d.AsSpan((int)o, 2));
    private uint U32(long o) => BinaryPrimitives.ReadUInt32LittleEndian(_d.AsSpan((int)o, 4));
    private ulong U64(long o) => BinaryPrimitives.ReadUInt64LittleEndian(_d.AsSpan((int)o, 8));

    private void Parse()
    {
        if (_d.Length < 0x40 || _d[0] != 'M' || _d[1] != 'Z') throw new FormatException("missing MZ header");
        var peOff = U32(0x3C);
        if (peOff > _d.Length - 24 || U32(peOff) != 0x00004550) throw new FormatException("missing PE signature");
        var coff = peOff + 4;
        Machine = U16(coff);
        var nSections = U16(coff + 2);
        TimeDateStamp = U32(coff + 4);
        var optSize = U16(coff + 16);
        var characteristics = U16(coff + 18);
        IsDll = (characteristics & 0x2000) != 0;

        var opt = coff + 20;
        var magic = U16(opt);
        Is64 = magic == 0x20B;
        if (magic != 0x10B && magic != 0x20B) throw new FormatException("invalid optional header");
        var ddOff = opt + (Is64 ? 112 : 96);
        var nDirs = U32(ddOff - 4);
        (uint, uint) Dir(int i) => i < nDirs ? (U32(ddOff + i * 8), U32(ddOff + i * 8 + 4)) : (0u, 0u);

        var secOff = opt + optSize;
        long endOfData = 0;
        for (int i = 0; i < Math.Min((int)nSections, 96); i++)
        {
            var s = secOff + i * 40;
            var name = Encoding.ASCII.GetString(_d, (int)s, 8).TrimEnd('\0');
            var sec = new Section(name, U32(s + 12), U32(s + 8), U32(s + 20), U32(s + 16), U32(s + 36));
            Sections.Add(sec);
            endOfData = Math.Max(endOfData, (long)sec.RawPointer + sec.RawSize);
        }

        SecurityDirectory = Dir(4);
        IsDotNet = Dir(14).Item1 != 0;
        var certEnd = SecurityDirectory.Rva != 0 ? (long)SecurityDirectory.Rva + SecurityDirectory.Size : 0;
        OverlaySize = Math.Max(0, _d.Length - Math.Max(endOfData, certEnd));

        ParseImports(Dir(1).Item1);
    }

    private long RvaToOffset(uint rva)
    {
        foreach (var s in Sections)
        {
            var size = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                return rva - s.VirtualAddress + s.RawPointer;
        }
        return rva < _d.Length ? rva : -1;
    }

    private string ReadCString(long off, int max = 256)
    {
        if (off < 0 || off >= _d.Length) return "";
        var end = (int)off;
        while (end < _d.Length && end - off < max && _d[end] != 0) end++;
        return Encoding.ASCII.GetString(_d, (int)off, end - (int)off);
    }

    private void ParseImports(uint rva)
    {
        if (rva == 0) return;
        var off = RvaToOffset(rva);
        if (off < 0) return;
        for (int i = 0; i < 512; i++, off += 20)
        {
            if (off + 20 > _d.Length) break;
            var origThunk = U32(off);
            var nameRva = U32(off + 12);
            var firstThunk = U32(off + 16);
            if (nameRva == 0 && firstThunk == 0) break;
            var dll = ReadCString(RvaToOffset(nameRva)).ToLowerInvariant();
            var thunk = RvaToOffset(origThunk != 0 ? origThunk : firstThunk);
            if (thunk < 0) continue;
            for (int j = 0; j < 4096; j++)
            {
                var step = Is64 ? 8 : 4;
                if (thunk + step > _d.Length) break;
                ulong val = Is64 ? U64(thunk) : U32(thunk);
                if (val == 0) break;
                var ordinal = Is64 ? (val & 0x8000000000000000UL) != 0 : (val & 0x80000000UL) != 0;
                if (!ordinal)
                {
                    var hint = RvaToOffset((uint)(val & 0x7FFFFFFF));
                    if (hint >= 0) Imports.Add((dll, ReadCString(hint + 2)));
                }
                thunk += step;
            }
        }
    }
}
