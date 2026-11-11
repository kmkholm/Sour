using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Sour.Core;

namespace Sour.Av
{
    /// <summary>One detection rule from Data\rules.json (or the user's rules_user.json).</summary>
    public sealed class RuleDef
    {
        public string id;
        public string name;
        public int score = 60;                 // ≥80 malicious, 40..79 suspicious
        public string target = "any";          // any | pe | script | lnk | text
        public string en, ar;                  // what the rule means, both languages
        public string mitre;
        /// <summary>named string groups; a value is one pattern literal or an array of alternatives (any alternative satisfies the group)</summary>
        public Dictionary<string, JsonElement> strings = new Dictionary<string, JsonElement>();
        public int min;                        // how many distinct groups must match; 0 = all

        public IEnumerable<string> Alternatives(string group)
        {
            if (!strings.TryGetValue(group, out var v)) yield break;
            if (v.ValueKind == JsonValueKind.String) yield return v.GetString();
            else if (v.ValueKind == JsonValueKind.Array) foreach (var e in v.EnumerateArray()) if (e.ValueKind == JsonValueKind.String) yield return e.GetString();
        }
        public bool unsigned_only;             // skip files with a valid Authenticode signature
        public string[] ext;                   // restrict to these extensions
        public string[] imports_all;           // PE import names that must all be present
        public int max_kb;                     // only files up to this size (0 = any)
    }

    public sealed class RuleHit
    {
        public RuleDef Rule; public List<string> Matched = new List<string>();
    }

    /// <summary>
    /// Multi-pattern signature engine: all strings of all rules are compiled into one Aho-Corasick automaton, so a file
    /// is read once regardless of the number of rules. Pattern syntax in rules.json: "t:text", "r:txet" (stored reversed so
    /// that the rule file itself is not mistaken for malware by other scanners), "h:4d5a90" (hex bytes); add "i" for
    /// case-insensitive and "w" to also match UTF-16LE, e.g. "riw:llehsrewop".
    /// </summary>
    public sealed class RuleEngine
    {
        sealed class Pat { public byte[] Lower, Exact; public bool CaseSensitive; public int Rule, Str; }

        public List<RuleDef> Rules = new List<RuleDef>();
        readonly List<Pat> _pats = new List<Pat>();
        readonly List<string[]> _strNames = new List<string[]>();
        int[] _go; int[][] _out;
        static readonly byte[] LowerTable = BuildLower();

        static byte[] BuildLower()
        {
            var t = new byte[256];
            for (int i = 0; i < 256; i++) t[i] = (byte)(i >= 'A' && i <= 'Z' ? i + 32 : i);
            return t;
        }

        static RuleEngine _inst;
        public static RuleEngine Instance => _inst ??= LoadDefault();
        public static void Reload() { _inst = null; }

        public static RuleEngine LoadDefault()
        {
            var e = new RuleEngine();
            e.AddFile(Path.Combine(Paths.DataDir, "rules.json"));
            e.AddFile(Path.Combine(Paths.Root, "rules_user.json"));
            e.Compile();
            return e;
        }

        public void AddFile(string file)
        {
            try
            {
                if (!File.Exists(file)) return;
                var list = JsonSerializer.Deserialize<List<RuleDef>>(File.ReadAllText(file, Encoding.UTF8), Json.Opt);
                if (list != null) Rules.AddRange(list.Where(r => !string.IsNullOrEmpty(r.id)));
            }
            catch (Exception ex) { Log.Debug("rules load " + file + ": " + ex.Message); }
        }

        /// <summary>Decodes one pattern literal. Returns (bytes, caseInsensitive, wide).</summary>
        public static (byte[] bytes, bool nocase, bool wide) Decode(string lit)
        {
            int c = lit.IndexOf(':');
            if (c < 1) return (Encoding.UTF8.GetBytes(lit), false, false);
            string flags = lit.Substring(0, c), body = lit.Substring(c + 1);
            bool nocase = flags.Contains('i'), wide = flags.Contains('w');
            byte[] b;
            switch (flags[0])
            {
                case 'r': { var a = body.ToCharArray(); Array.Reverse(a); b = Encoding.UTF8.GetBytes(new string(a)); break; }
                case 'h': b = Convert.FromHexString(body.Replace(" ", "")); break;
                default: b = Encoding.UTF8.GetBytes(body); break;
            }
            return (b, nocase, wide);
        }

        public static string Encode(string plain, bool nocase = true, bool wide = false)
        {
            var a = plain.ToCharArray(); Array.Reverse(a);
            return "r" + (nocase ? "i" : "") + (wide ? "w" : "") + ":" + new string(a);
        }

        public void Compile()
        {
            _pats.Clear(); _strNames.Clear();
            for (int ri = 0; ri < Rules.Count; ri++)
            {
                var names = Rules[ri].strings.Keys.ToArray();
                _strNames.Add(names);
                for (int si = 0; si < names.Length; si++)
                {
                    foreach (string lit in Rules[ri].Alternatives(names[si]))
                    {
                        try
                        {
                            var (b, nocase, wide) = Decode(lit);
                            if (b.Length < 3) continue;       // too short to be a meaningful signature
                            Add(b, nocase, ri, si);
                            if (wide) { var w = new byte[b.Length * 2]; for (int i = 0; i < b.Length; i++) w[i * 2] = b[i]; Add(w, nocase, ri, si); }
                        }
                        catch { }
                    }
                }
            }
            Build();
        }

        void Add(byte[] exact, bool nocase, int rule, int str)
        {
            var lower = new byte[exact.Length];
            for (int i = 0; i < exact.Length; i++) lower[i] = LowerTable[exact[i]];
            _pats.Add(new Pat { Exact = exact, Lower = lower, CaseSensitive = !nocase, Rule = rule, Str = str });
        }

        void Build()
        {
            var go = new List<int[]>(); var outs = new List<List<int>>();
            int NewState() { var a = new int[256]; Array.Fill(a, -1); go.Add(a); outs.Add(null); return go.Count - 1; }
            NewState();
            for (int pi = 0; pi < _pats.Count; pi++)
            {
                int s = 0;
                foreach (byte b in _pats[pi].Lower) { if (go[s][b] < 0) go[s][b] = NewState(); s = go[s][b]; }
                (outs[s] ??= new List<int>()).Add(pi);
            }
            var fail = new int[go.Count];
            var q = new Queue<int>();
            for (int b = 0; b < 256; b++) { int t = go[0][b]; if (t < 0) go[0][b] = 0; else { fail[t] = 0; q.Enqueue(t); } }
            while (q.Count > 0)
            {
                int s = q.Dequeue();
                for (int b = 0; b < 256; b++)
                {
                    int t = go[s][b];
                    if (t < 0) { go[s][b] = go[fail[s]][b]; continue; }
                    fail[t] = go[fail[s]][b];
                    if (outs[fail[t]] != null) (outs[t] ??= new List<int>()).AddRange(outs[fail[t]]);
                    q.Enqueue(t);
                }
            }
            _go = new int[go.Count * 256];
            for (int s = 0; s < go.Count; s++) Buffer.BlockCopy(go[s], 0, _go, s * 256 * sizeof(int), 256 * sizeof(int));
            _out = outs.Select(o => o?.Distinct().ToArray()).ToArray();
        }

        /// <summary>Scans a buffer and returns the rules whose string and structural conditions are met.</summary>
        public List<RuleHit> Scan(byte[] data, string kind, string ext, bool signedValid, PeFile pe)
        {
            var hits = new List<RuleHit>();
            if (Rules.Count == 0 || _go == null) return hits;
            var matched = new HashSet<long>();
            int state = 0;
            var go = _go; var lower = LowerTable;
            for (int i = 0; i < data.Length; i++)
            {
                state = go[state * 256 + lower[data[i]]];
                var o = _out[state];
                if (o == null) continue;
                foreach (int pi in o)
                {
                    var p = _pats[pi];
                    long key = ((long)p.Rule << 20) | (uint)p.Str;
                    if (matched.Contains(key)) continue;
                    if (p.CaseSensitive)
                    {
                        int start = i - p.Exact.Length + 1; bool ok = true;
                        for (int k = 0; k < p.Exact.Length; k++) if (data[start + k] != p.Exact[k]) { ok = false; break; }
                        if (!ok) continue;
                    }
                    matched.Add(key);
                }
            }

            HashSet<string> imports = null;
            for (int ri = 0; ri < Rules.Count; ri++)
            {
                var r = Rules[ri];
                if (r.unsigned_only && signedValid) continue;
                // indicator-name rules are written for binaries; a document that discusses a tool is not that tool
                if (kind == "text" && r.unsigned_only) continue;
                if (r.target != "any" && r.target != kind) continue;
                if (r.ext != null && r.ext.Length > 0 && !r.ext.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                if (r.max_kb > 0 && data.Length > r.max_kb * 1024L) continue;
                var names = _strNames[ri];
                var got = new List<string>();
                for (int si = 0; si < names.Length; si++) if (matched.Contains(((long)ri << 20) | (uint)si)) got.Add(names[si]);
                int need = r.min <= 0 ? names.Length : r.min;
                if (names.Length > 0 && got.Count < need) continue;
                if (r.imports_all != null && r.imports_all.Length > 0)
                {
                    if (pe == null || !pe.Valid) continue;
                    imports ??= new HashSet<string>(pe.Imports.SelectMany(kv => kv.Value), StringComparer.Ordinal);
                    if (!r.imports_all.All(a => imports.Contains(a) || imports.Contains(a + "A") || imports.Contains(a + "W"))) continue;
                }
                else if (names.Length == 0) continue;
                hits.Add(new RuleHit { Rule = r, Matched = got });
            }
            return hits;
        }
    }
}
