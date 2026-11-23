using System.Reflection;

namespace VMProtector.Core;

internal static class EmbeddedAssets
{
    public static byte[] LoadRuntimeAssemblyBytes() => LoadResource("VMProtector.Core.Embedded.VMProtector.Runtime.dll");

    public static byte[] LoadNativeStubBytes(bool isGui)
    {
        string res = isGui
            ? "VMProtector.Core.Embedded.VMProtector.NativeStub.Gui.exe"
            : "VMProtector.Core.Embedded.VMProtector.NativeStub.Console.exe";
        return LoadResource(res);
    }

    private static byte[] LoadResource(string name)
    {
        Assembly asm = typeof(EmbeddedAssets).Assembly;
        using Stream? s = asm.GetManifestResourceStream(name);
        if (s == null)
        {
            throw new InvalidOperationException($"Missing embedded asset: {name}");
        }
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
