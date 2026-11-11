using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Sour.Core;

namespace Sour.Av
{
    public sealed class QuarantineItem
    {
        public string Id = Guid.NewGuid().ToString("N");
        public string OriginalPath, Sha256, Threat, Summary;
        public Verdict Verdict; public int Score; public long Size;
        public DateTime Time = DateTime.Now;
        public string Key, Iv;       // AES key for the stored copy: neutralises the file, it is not a secret
    }

    public sealed class QuarantineIndex { public List<QuarantineItem> Items = new List<QuarantineItem>(); }

    /// <summary>
    /// Quarantine vault: the file is AES-encrypted into %LOCALAPPDATA%\Sour\Quarantine (so it can neither run nor be
    /// re-detected) and removed from its original place. Items can be restored byte-for-byte or deleted for good.
    /// </summary>
    public static class Quarantine
    {
        static readonly object Gate = new object();
        static string IndexFile => Path.Combine(Paths.Quarantine, "index.json");
        static QuarantineIndex _idx;
        static QuarantineIndex Idx => _idx ??= Json.Load<QuarantineIndex>(IndexFile);
        public static event Action Changed;
        public static void Reload() { lock (Gate) _idx = null; }

        public static List<QuarantineItem> Items { get { lock (Gate) return Idx.Items.OrderByDescending(i => i.Time).ToList(); } }

        public static (bool ok, string error, QuarantineItem item) Add(ScanResult r)
        {
            try
            {
                if (!File.Exists(r.Path)) return (false, "file no longer exists", null);
                byte[] data = File.ReadAllBytes(r.Path);
                using var aes = Aes.Create();
                var item = new QuarantineItem
                {
                    OriginalPath = r.Path, Sha256 = r.Sha256 ?? Util.Sha256(data), Threat = r.Threat, Summary = r.Summary,
                    Verdict = r.Verdict, Score = r.Score, Size = data.Length,
                    Key = Convert.ToBase64String(aes.Key), Iv = Convert.ToBase64String(aes.IV),
                };
                File.WriteAllBytes(Path.Combine(Paths.Quarantine, item.Id + ".sourq"), aes.EncryptCbc(data, aes.IV));
                try
                {
                    File.SetAttributes(r.Path, FileAttributes.Normal);
                    File.Delete(r.Path);
                }
                catch (Exception ex)
                {
                    File.Delete(Path.Combine(Paths.Quarantine, item.Id + ".sourq"));
                    return (false, "could not remove the original (in use?): " + ex.Message, null);
                }
                lock (Gate) { Idx.Items.Add(item); Json.Save(IndexFile, Idx); }
                Log.Add(EventKind.Antivirus, Severity.High, "av.quarantined", "File moved to quarantine", "نُقل الملف إلى الحجر الصحي", $"{r.Path}\n{item.Threat} · sha256={item.Sha256}", r.Path);
                Changed?.Invoke();
                return (true, null, item);
            }
            catch (Exception ex) { return (false, ex.Message, null); }
        }

        public static (bool ok, string error) Restore(string id, string toPath = null)
        {
            try
            {
                QuarantineItem item;
                lock (Gate) item = Idx.Items.FirstOrDefault(i => i.Id == id);
                if (item == null) return (false, "not found");
                string blob = Path.Combine(Paths.Quarantine, id + ".sourq");
                using var aes = Aes.Create();
                aes.Key = Convert.FromBase64String(item.Key);
                byte[] data = aes.DecryptCbc(File.ReadAllBytes(blob), Convert.FromBase64String(item.Iv));
                if (Util.Sha256(data) != item.Sha256) return (false, "integrity check failed");
                string dest = toPath ?? item.OriginalPath;
                Directory.CreateDirectory(Path.GetDirectoryName(dest));
                if (File.Exists(dest)) return (false, "a file already exists at the original location");
                File.WriteAllBytes(dest, data);
                File.Delete(blob);
                lock (Gate) { Idx.Items.Remove(item); Json.Save(IndexFile, Idx); }
                Log.Add(EventKind.Antivirus, Severity.Medium, "av.restored", "File restored from quarantine", "استُعيد الملف من الحجر الصحي", dest, dest);
                Changed?.Invoke();
                return (true, null);
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        public static bool Delete(string id)
        {
            try
            {
                lock (Gate)
                {
                    var item = Idx.Items.FirstOrDefault(i => i.Id == id);
                    if (item == null) return false;
                    try { File.Delete(Path.Combine(Paths.Quarantine, id + ".sourq")); } catch { }
                    Idx.Items.Remove(item); Json.Save(IndexFile, Idx);
                }
                Changed?.Invoke();
                return true;
            }
            catch { return false; }
        }
    }
}
