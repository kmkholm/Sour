using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Sour.Core;

namespace Sour.Av
{
    public sealed class MlTree { public int[] f; public double[] t; public int[] l; public int[] r; public double[] v; public double[] leaf; }

    public sealed class MlModelFile
    {
        public string format; public string[] features; public MlTree[] trees;
        public double threshold_malicious, threshold_suspicious;
    }

    public sealed class MlCardThreshold { public double threshold, tpr, fpr; public int tp, fp; }
    public sealed class MlCardFeature { public string name; public double gain; }
    public sealed class MlCard
    {
        public string name, algorithm, trained, dataset, sampling, threshold_rule;
        public int n_features, n_trees, n_train, n_val, n_test;
        public double val_auc, test_auc, threshold_malicious, threshold_suspicious;
        public MlCardThreshold test_at_malicious, test_at_suspicious;
        public string[] train_weeks, val_weeks, test_weeks;
        public Dictionary<string, JsonElement> per_type;
        public MlCardFeature[] top_features;
    }

    public sealed class MlScore
    {
        public double Prob;
        public List<(string name, double contribution, double value)> Top = new List<(string, double, double)>();
    }

    /// <summary>
    /// Gradient-boosted decision trees (trained with LightGBM on EMBER2024, exported to JSON) evaluated in pure C#.
    /// Explanations use the Saabas path attribution: each split moves the expected value, and that move is
    /// credited to the split feature - so every score comes with the features that drove it.
    /// </summary>
    public sealed class MlModel
    {
        public MlModelFile File;
        public MlCard Card;
        public bool Loaded => File?.trees != null && File.trees.Length > 0;
        public double ThresholdMalicious => Settings.Current.AvMlMalicious > 0 ? Settings.Current.AvMlMalicious : File.threshold_malicious;
        public double ThresholdSuspicious => Settings.Current.AvMlSuspicious > 0 ? Settings.Current.AvMlSuspicious : File.threshold_suspicious;

        static MlModel _inst;
        public static MlModel Instance => _inst ??= Load(Path.Combine(Paths.DataDir, "sour_model.json"), Path.Combine(Paths.DataDir, "model_card.json"));

        public static MlModel Load(string modelPath, string cardPath)
        {
            var m = new MlModel();
            try
            {
                if (System.IO.File.Exists(modelPath))
                {
                    using var fs = System.IO.File.OpenRead(modelPath);
                    m.File = JsonSerializer.Deserialize<MlModelFile>(fs, Json.Opt);
                    if (m.File?.features == null || !m.File.features.SequenceEqual(PeFeatures.Names))
                    {
                        Log.Debug("model feature list does not match this build - model ignored");
                        m.File = null;
                    }
                }
                if (System.IO.File.Exists(cardPath)) m.Card = JsonSerializer.Deserialize<MlCard>(System.IO.File.ReadAllText(cardPath), Json.Opt);
            }
            catch (Exception ex) { Log.Debug("model load: " + ex.Message); m.File = null; }
            return m;
        }

        public double Predict(double[] x)
        {
            double raw = 0;
            foreach (var t in File.trees)
            {
                if (t.f.Length == 0) { raw += t.leaf[0]; continue; }
                int n = 0;
                while (n >= 0) n = x[t.f[n]] <= t.t[n] ? t.l[n] : t.r[n];
                raw += t.leaf[~n];
            }
            return 1.0 / (1.0 + Math.Exp(-raw));
        }

        public MlScore Explain(double[] x, int top = 6)
        {
            var contrib = new double[x.Length];
            double raw = 0;
            foreach (var t in File.trees)
            {
                if (t.f.Length == 0) { raw += t.leaf[0]; continue; }
                int n = 0;
                while (true)
                {
                    int next = x[t.f[n]] <= t.t[n] ? t.l[n] : t.r[n];
                    double nv = next >= 0 ? t.v[next] : t.leaf[~next];
                    contrib[t.f[n]] += nv - t.v[n];
                    if (next < 0) { raw += nv; break; }
                    n = next;
                }
            }
            var s = new MlScore { Prob = 1.0 / (1.0 + Math.Exp(-raw)) };
            foreach (int i in Enumerable.Range(0, x.Length).OrderByDescending(i => contrib[i]).Take(top))
                if (contrib[i] > 0.05) s.Top.Add((File.features[i], contrib[i], x[i]));
            return s;
        }
    }
}
