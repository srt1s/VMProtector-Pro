using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using VMProtector.Core;

namespace VMProtector.GUI;

public partial class MainWindow : Window
{
    private bool _updatingPreset;

    public MainWindow()
    {
        InitializeComponent();
        AppendLog("VMProtector-Pro v2.0 hazır. .NET 8 SingleFile, .NET Assembly ve x64 Native PE desteklenir.");
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            LoadInputFile(files[0]);
        }
    }

    private void BtnBrowseInput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Korunacak Binary Dosyasını Seçin",
            Filter = "Executable & Libraries (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            LoadInputFile(dlg.FileName);
        }
    }

    private void BtnBrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Title = "Korumalı Çıkış Dosyası",
            Filter = "Executable (*.exe)|*.exe|Assembly (*.dll)|*.dll|All files (*.*)|*.*",
            FileName = Path.GetFileName(TxtOutputPath.Text)
        };
        if (dlg.ShowDialog() == true)
        {
            TxtOutputPath.Text = dlg.FileName;
        }
    }

    private void LoadInputFile(string path)
    {
        TxtInputPath.Text = path;
        string dir = Path.GetDirectoryName(path) ?? ".";
        string name = Path.GetFileNameWithoutExtension(path);
        string ext = Path.GetExtension(path);
        TxtOutputPath.Text = Path.Combine(dir, $"{name}_vmp{ext}");

        try
        {
            BinaryInfo info = BinaryInspector.Inspect(path);
            TxtBadgeMode.Text = $"MOD: {info.Kind}";
            string summary =
                $"Tür: {info.Kind} | Mimari: {info.Architecture} ({info.Subsystem})\n" +
                $"Boyut: {info.FileSize / 1048576.0:F2} MB ({info.FileSize:N0} B) | Entropi: {info.ShannonEntropy:F4} bit/byte";

            if (!string.IsNullOrEmpty(info.EntryAssemblyName))
            {
                summary += $"\nAssembly: {info.EntryAssemblyName} ({info.TargetFramework}, WPF={info.IsWpf})\n" +
                           $"Tipler: {info.TotalTypes:N0} | Metotlar: {info.TotalMethods:N0} | VM Uyumlu: {info.EligibleVmMethods:N0}";
            }
            if (info.Kind == BinaryKind.NativePe64)
            {
                CmbPreset.SelectedIndex = 3;
            }
            TxtInspectSummary.Text = summary;
            AppendLog($"Analiz edildi: {Path.GetFileName(path)} -> {info.Kind}");
        }
        catch (Exception ex)
        {
            TxtInspectSummary.Text = $"Analiz hatası: {ex.Message}";
            AppendLog($"[HATA] Analiz başarısız: {ex.Message}");
        }
    }

    private void CmbPreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingPreset || !IsLoaded) return;
        _updatingPreset = true;
        try
        {
            ProtectionPreset preset = CmbPreset.SelectedIndex switch
            {
                1 => ProtectionPreset.BalancedSafe,
                2 => ProtectionPreset.MaximumStealth,
                3 => ProtectionPreset.NativePe64,
                _ => ProtectionPreset.ToprakExternalMaximum
            };
            ProtectionOptions opt = ProtectionOptions.FromPreset(preset);
            ChkVm.IsChecked = opt.EnableMethodVirtualization;
            ChkStrings.IsChecked = opt.EnableStringEncryption;
            ChkCfg.IsChecked = opt.EnableControlFlowObfuscation;
            ChkConst.IsChecked = opt.EnableConstantMutation;
            ChkRename.IsChecked = opt.EnableSymbolRenaming;
            ChkAntiDebug.IsChecked = opt.EnableAntiDebug;
            ChkAntiIldasm.IsChecked = opt.EnableAntiIldasmAndStrip;
            ChkStage2.IsChecked = opt.EnableSingleFileStage2Loader;
            ChkToolScan.IsChecked = opt.EnableToolProcessScan;
        }
        finally
        {
            _updatingPreset = false;
        }
    }

    private async void BtnProtect_Click(object sender, RoutedEventArgs e)
    {
        string input = TxtInputPath.Text.Trim();
        string output = TxtOutputPath.Text.Trim();
        if (string.IsNullOrEmpty(input) || !File.Exists(input))
        {
            MessageBox.Show("Lütfen geçerli bir giriş dosyası seçin.", "VMProtector-Pro", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(output))
        {
            MessageBox.Show("Lütfen çıkış dosya yolu belirleyin.", "VMProtector-Pro", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var options = new ProtectionOptions
        {
            EnableMethodVirtualization = ChkVm.IsChecked == true,
            EnableStringEncryption = ChkStrings.IsChecked == true,
            EnableControlFlowObfuscation = ChkCfg.IsChecked == true,
            EnableConstantMutation = ChkConst.IsChecked == true,
            EnableSymbolRenaming = ChkRename.IsChecked == true,
            EnableAntiDebug = ChkAntiDebug.IsChecked == true,
            EnableAntiIldasmAndStrip = ChkAntiIldasm.IsChecked == true,
            EnableSingleFileStage2Loader = ChkStage2.IsChecked == true,
            EnableToolProcessScan = ChkToolScan.IsChecked == true,
            PriorityScopeFilters = TxtScopeFilter.Text
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList()
        };

        BtnProtect.IsEnabled = false;
        PrgBuild.Value = 0;
        TxtLog.Clear();
        AppendLog($"Koruma başlatılıyor: {Path.GetFileName(input)}");

        var pipeline = new ProtectorPipeline
        {
            OnProgress = (pct, msg) => Dispatcher.Invoke(() =>
            {
                PrgBuild.Value = pct * 100.0;
                TxtStatus.Text = msg;
                AppendLog($"[{pct * 100,5:F1}%] {msg}");
            })
        };

        ProtectionReport report = await Task.Run(() => pipeline.Protect(input, output, options));

        BtnProtect.IsEnabled = true;
        if (!report.Success)
        {
            MessageBox.Show($"Koruma başarısız:\n{report.ErrorMessage}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        AppendLog("\n=== KORUMA RAPORU ===");
        AppendLog($"Süre          : {report.Elapsed.TotalSeconds:F2} sn");
        AppendLog($"Boyut         : {report.InputSize:N0} B -> {report.OutputSize:N0} B");
        AppendLog($"Entropi       : {report.InputEntropy:F4} -> {report.OutputEntropy:F4} bit/byte");
        if (report.NativePe64Protected)
        {
            AppendLog("Native PE64   : C++20 Polymorphic Key VM + ChaCha20 + Reflective RAM Loader");
        }
        else
        {
            AppendLog($"VM Metotlar   : {report.VirtualizedMethods} sanallaştırıldı ({report.SkippedVmMethods} atlandı)");
            AppendLog($"Control Flow  : {report.FlattenedMethods} metot düzleştirildi");
            AppendLog($"Şifreli Metin : {report.EncryptedStrings} adet (ChaCha20)");
            AppendLog($"Sabit Mutasyon: {report.MutatedConstants} adet");
            AppendLog($"İsim Gizleme  : {report.RenamedTypes} tip, {report.RenamedMethods} metot, {report.RenamedFields} alan");
            AppendLog($"Stage-2 RAM   : {(report.Stage2InMemoryBundleApplied ? "Aktif (Anti-SingleFileExtractor)" : "Pasif")}");
        }
        TxtStatus.Text = $"Tamamlandı ({report.Elapsed.TotalSeconds:F2} sn)";
    }

    private void BtnOpenOutDir_Click(object sender, RoutedEventArgs e)
    {
        string path = TxtOutputPath.Text.Trim();
        string? dir = File.Exists(path) ? Path.GetDirectoryName(path) : Path.GetDirectoryName(TxtInputPath.Text.Trim());
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
        }
    }

    private void AppendLog(string line)
    {
        TxtLog.AppendText(line + Environment.NewLine);
        TxtLog.ScrollToEnd();
    }
}
