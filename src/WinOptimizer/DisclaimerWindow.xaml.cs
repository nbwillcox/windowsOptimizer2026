using System.Windows;

namespace WinOptimizer
{
    public partial class DisclaimerWindow : Window
    {
        public DisclaimerWindow()
        {
            InitializeComponent();
        }

        void Agree_Changed(object sender, RoutedEventArgs e)
        {
            AcceptBtn.IsEnabled = AgreeBox.IsChecked == true;
        }

        void Accept_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }
    }
}
