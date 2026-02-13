namespace ProjekatZastita
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent() //sadrzi inicijalizaciju UI komponenti, dok se poslovna logika nalazi u Form1.cs fajlu
        {
            components = new System.ComponentModel.Container();
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(1000, 650);
            this.Text = "Form1";
        }

    }
}
