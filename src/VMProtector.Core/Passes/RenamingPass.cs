using System.Resources;
using System.Text.RegularExpressions;
using AsmResolver.DotNet;

namespace VMProtector.Core.Passes;

internal static class RenamingPass
{
    public sealed class Result
    {
        public int Types { get; set; }
        public int Methods { get; set; }
        public int Fields { get; set; }
    }

    public static Result Execute(ModuleDefinition module, RuntimeHandles rt)
    {
        var result = new Result();
        var protectedNames = CollectWpfAndMetadataProtectedNames(module);

        bool isLibrary = (module.Assembly != null && (module.Assembly.Attributes & AsmResolver.PE.DotNet.Metadata.Tables.AssemblyAttributes.PublicKey) != 0) ||
                         module.ManagedEntryPointMethod == null;

        int typeCounter = 0;
        int memberCounter = 0;

        foreach (TypeDefinition type in module.GetAllTypes())
        {
            if (rt.RuntimeTypes.Contains(type) || type.IsModuleType) continue;

            string typeName = type.Name?.ToString() ?? "";
            bool hasObfExclude = HasExcludeAttribute(type);
            bool isSpecialWpfOrEntry =
                protectedNames.Contains(typeName) ||
                typeName.Contains("AnonymousType", StringComparison.Ordinal) ||
                typeName.StartsWith("<", StringComparison.Ordinal) ||
                InheritsWpfRoot(type);

            if (!hasObfExclude && !isSpecialWpfOrEntry)
            {
                if (!isLibrary || (!type.IsPublic && !type.IsNestedPublic))
                {
                    if (!type.IsNested)
                    {
                        type.Namespace = "";
                    }
                    type.Name = GenerateName(ref typeCounter);
                    result.Types++;
                }
            }

            bool skipMemberRename = hasObfExclude || isSpecialWpfOrEntry || type.IsEnum;

            foreach (FieldDefinition field in type.Fields)
            {
                if (skipMemberRename || field.IsSpecialName || field.IsRuntimeSpecialName) continue;
                string fName = field.Name?.ToString() ?? "";
                if (protectedNames.Contains(fName) || HasExcludeAttribute(field)) continue;
                if (isLibrary && field.IsPublic) continue;

                field.Name = GenerateName(ref memberCounter);
                result.Fields++;
            }

            foreach (MethodDefinition m in type.Methods)
            {
                // Always clear parameter metadata names safely unless PInvoke
                if (!m.IsPInvokeImpl)
                {
                    foreach (var p in m.ParameterDefinitions)
                    {
                        p.Name = null;
                    }
                }

                if (skipMemberRename) continue;
                if (m.IsConstructor || m.IsVirtual || m.IsAbstract || m.IsSpecialName || m.IsRuntimeSpecialName || m.IsPInvokeImpl) continue;
                if (ReferenceEquals(m, module.ManagedEntryPointMethod)) continue;
                string mName = m.Name?.ToString() ?? "";
                if (protectedNames.Contains(mName) || HasExcludeAttribute(m)) continue;
                if (isLibrary && m.IsPublic) continue;

                m.Name = GenerateName(ref memberCounter);
                result.Methods++;
            }
        }

        return result;
    }

    private static string GenerateName(ref int index)
    {
        int n = index++;
        const string alphabet = "Il1O0o"; // visually confusing compact identifier scheme
        Span<char> buf = stackalloc char[12];
        buf[0] = '_';
        int pos = 1;
        int v = n + 1;
        while (v > 0 && pos < buf.Length)
        {
            buf[pos++] = alphabet[v % alphabet.Length];
            v /= alphabet.Length;
        }
        buf[pos++] = (char)('a' + (n % 26));
        return new string(buf[..pos]);
    }

    private static bool InheritsWpfRoot(TypeDefinition type)
    {
        ITypeDefOrRef? bt = type.BaseType;
        while (bt != null)
        {
            string fn = bt.FullName ?? "";
            if (fn is "System.Windows.Application" or "System.Windows.Window" or "System.Windows.Controls.UserControl"
                or "System.Windows.Controls.Page" or "System.Windows.ResourceDictionary")
            {
                return true;
            }
            TypeDefinition? resolved = bt as TypeDefinition ?? bt.Resolve();
            bt = resolved?.BaseType;
        }
        return false;
    }

    private static bool HasExcludeAttribute(IHasCustomAttribute target)
    {
        foreach (CustomAttribute ca in target.CustomAttributes)
        {
            string name = ca.Constructor?.DeclaringType?.Name?.ToString() ?? "";
            if (name.Contains("Obfuscation", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("GeneratedCode", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static HashSet<string> CollectWpfAndMetadataProtectedNames(ModuleDefinition module)
    {
        var names = new HashSet<string>(StringComparer.Ordinal)
        {
            "App", "MainWindow", "ActivationWindow", "UpdateWindow", "SplashWindow"
        };

        // Scan *.g.resources (BAML) so every XAML type name, x:Name, event handler stays intact
        foreach (ManifestResource res in module.Resources)
        {
            if (res.Name?.ToString().EndsWith(".g.resources", StringComparison.OrdinalIgnoreCase) != true) continue;
            try
            {
                byte[]? bytes = res.GetData();
                if (bytes == null) continue;
                using var ms = new MemoryStream(bytes);
                using var rr = new ResourceReader(ms);
                var en = rr.GetEnumerator();
                while (en.MoveNext())
                {
                    if (en.Value is Stream bamlStream)
                    {
                        using var bms = new MemoryStream();
                        bamlStream.CopyTo(bms);
                        ExtractAsciiAndUtf16Tokens(bms.ToArray(), names);
                    }
                    else if (en.Key is string keyStr)
                    {
                        names.Add(Path.GetFileNameWithoutExtension(keyStr));
                    }
                }
            }
            catch { }
        }

        return names;
    }

    private static void ExtractAsciiAndUtf16Tokens(byte[] bamlBytes, HashSet<string> sink)
    {
        string ascii = System.Text.Encoding.Latin1.GetString(bamlBytes);
        foreach (Match m in Regex.Matches(ascii, @"[A-Za-z_][A-Za-z0-9_]{2,64}"))
        {
            sink.Add(m.Value);
        }
    }
}
