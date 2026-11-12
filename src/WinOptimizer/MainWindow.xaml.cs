using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Win32;

namespace WinOptimizer
{
    public partial class MainWindow : Window
    {
        class Pill
        {
            public string Key, Label;
            public override string ToString() => Label;
        }

        static readonly string[] CategoryOrder =
            { "Security", "Startup", "Services", "Windows settings", "Boot", "Memory", "Storage", "Hardware", "Unused programs" };

        ScanResult _result;
        bool _loading;

        public MainWindow()
        {
            InitializeComponent();
            AdminBanner.Visibility = Native.IsAdmin ? Visibility.Collapsed : Visibility.Visible;
            _loading = true;
            SortList.ItemsSource = new[]
            {
                new Pill { Key = "best", Label = "Best first" },
                new Pill { Key = "impact", Label = "Highest impact" },
                new Pill { Key = "easy", Label = "Easiest" },
                new Pill { Key = "safe", Label = "Safest" },
            };
            SortList.SelectedIndex = 0;
            _loading = false;
        }

        async void Scan_Click(object sender, RoutedEventArgs e)
        {
            ScanBtn.IsEnabled = ExportBtn.IsEnabled = false;
            Cards.ItemsSource = null;
            SummaryItems.Visibility = FilterPanel.Visibility = Visibility.Collapsed;
            StatusPanel.Visibility = Progress.Visibility = Visibility.Visible;
            StatusText.Text = "Starting scan...";
            Progress.IsIndeterminate = true; // animation runs only while scanning, so the app idles at zero CPU

            var progress = new Progress<string>(s => StatusText.Text = s);
            try
            {
                _result = await Task.Run(() => ScanEngine.Run(progress));
                ShowResult();
            }
            catch (Exception ex)
            {
                Progress.Visibility = Visibility.Collapsed;
                StatusText.Text = "The scan could not finish: " + ex.Message;
            }
            Progress.IsIndeterminate = false;
            ScanBtn.Content = "Scan again";
            ScanBtn.IsEnabled = true;
        }

        void ShowResult()
        {
            Progress.Visibility = Visibility.Collapsed;
            SummaryItems.ItemsSource = ScanEngine.SummaryRows(_result.Sys);
            SummaryItems.Visibility = Visibility.Visible;

            var pills = new List<Pill> { new Pill { Key = null, Label = "All (" + _result.Recs.Count + ")" } };
            var cats = _result.Recs.GroupBy(r => r.Category).ToDictionary(g => g.Key, g => g.Count());
            foreach (var c in CategoryOrder.Concat(cats.Keys.Except(CategoryOrder)))
                if (cats.TryGetValue(c, out int n)) pills.Add(new Pill { Key = c, Label = c + " (" + n + ")" });

            _loading = true;
            CategoryList.ItemsSource = pills;
            CategoryList.SelectedIndex = 0;
            _loading = false;

            FilterPanel.Visibility = Visibility.Visible;
            ExportBtn.IsEnabled = true;
            ApplyFilter();
        }

        void Filter_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (!_loading) ApplyFilter();
        }

        void ApplyFilter()
        {
            if (_result == null) return;
            string cat = (CategoryList.SelectedItem as Pill)?.Key;
            string sort = (SortList.SelectedItem as Pill)?.Key ?? "best";

            IEnumerable<Recommendation> q = _result.Recs;
            if (cat != null) q = q.Where(r => r.Category == cat);
            switch (sort)
            {
                case "impact": q = q.OrderByDescending(r => r.Impact).ThenBy(r => r.Risk).ThenBy(r => r.Difficulty); break;
                case "easy": q = q.OrderBy(r => r.Difficulty).ThenByDescending(r => r.Impact).ThenBy(r => r.Risk); break;
                case "safe": q = q.OrderBy(r => r.Risk).ThenByDescending(r => r.Impact).ThenBy(r => r.Difficulty); break;
                default: q = q.OrderByDescending(r => r.Score).ThenByDescending(r => r.Impact); break;
            }
            var list = q.ToList();
            Cards.ItemsSource = list;
            CountText.Text = list.Count + (list.Count == 1 ? " recommendation" : " recommendations") +
                             " · scanned in " + _result.Seconds.ToString("0.0") + " s";

            if (list.Count == 0)
            {
                StatusPanel.Visibility = Visibility.Visible;
                StatusText.Text = "Nothing to recommend here. This PC already looks well tuned.";
            }
            else StatusPanel.Visibility = Visibility.Collapsed;
        }

        void Export_Click(object sender, RoutedEventArgs e)
        {
            if (_result == null) return;
            var dlg = new SaveFileDialog
            {
                Title = "Save WinOptimizer report",
                Filter = "Web page (*.html)|*.html",
                FileName = "WinOptimizer-report-" + _result.When.ToString("yyyy-MM-dd") + ".html",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                File.WriteAllText(dlg.FileName, ScanEngine.BuildHtml(_result), Encoding.UTF8);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Could not save the report: " + ex.Message, "WinOptimizer", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        void Elevate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location) { UseShellExecute = true, Verb = "runas" });
                Application.Current.Shutdown();
            }
            catch (Win32Exception) { /* the user declined the Windows prompt; carry on as standard user */ }
        }

        /// <summary>Opens the Windows page named on the card. It only navigates there; the user makes the change.</summary>
        void Open_Click(object sender, RoutedEventArgs e)
        {
            string target = (sender as Button)?.Tag as string;
            if (string.IsNullOrEmpty(target)) return;
            var parts = target.Split(new[] { '|' }, 2);
            try
            {
                Process.Start(new ProcessStartInfo(parts[0], parts.Length > 1 ? parts[1] : "") { UseShellExecute = true });
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { /* user declined the Windows prompt */ }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Windows could not open that page (" + ex.Message + "). Follow the walkthrough on the card instead.",
                    "WinOptimizer", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        void Link_Navigate(object sender, RequestNavigateEventArgs e)
        {
            try { Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true }); } catch { }
            e.Handled = true;
        }
    }
}
