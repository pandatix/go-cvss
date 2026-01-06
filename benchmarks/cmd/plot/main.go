package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/tools/benchmark/parse"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
	"gonum.org/v1/plot/vg/vgsvg"
)

var (
	barWidth = vg.Points(14)
)

func main() {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Run the benchmarks
	fmt.Println("[+] Running benchmarks...")
	rd, err := runBenchmarks(ctx)
	if err != nil {
		fatal(err)
	}

	// 2. Process raw results into manipulable data
	fmt.Println("[+] Processing results...")
	data, err := process(rd)
	if err != nil {
		fatal(err)
	}

	// 3. Plot results and export
	fmt.Println("[+] Exporting...")
	plots := plotsPerVer(data)
	if err := export(data, plots); err != nil {
		fatal(err)
	}
}

// XXX issuing an exec call is not ideal, yet sufficient for a CI utility
func runBenchmarks(ctx context.Context) (io.Reader, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "./", "-run=^$", "-bench=.", "-benchmem")
	buf := &bytes.Buffer{}
	cmd.Stdout = io.MultiWriter(buf, os.Stdout)
	return buf, cmd.Run()
}

// Result per version, then per workflow, and finally per benchmarked implementation.
type Result map[string]map[string]map[string]Benchmark

// Benchmark for a single workflow and a single implementation.
type Benchmark struct {
	NsPerOp     float64 `json:"nsPerOp"`
	BytesPerOp  uint64  `json:"bytesPerOp"`
	AllocsPerOp uint64  `json:"allocsPerOp"`
}

func process(in io.Reader) (Result, error) {
	set, err := parse.ParseSet(in)
	if err != nil {
		return nil, err
	}

	res := Result{}
	for k, v := range set {
		if len(v) != 1 {
			return nil, errors.New("invalid benchmark format with duplicated benchmark name")
		}
		graw, rem, _ := strings.Cut(k, "/")
		ver, group, _ := strings.Cut(strings.TrimPrefix(graw, "Benchmark_"), "_")
		implem := cutRight(rem)

		if _, ok := res[ver]; !ok {
			res[ver] = map[string]map[string]Benchmark{}
		}
		if _, ok := res[ver][group]; !ok {
			res[ver][group] = map[string]Benchmark{}
		}
		res[ver][group][implem] = Benchmark{
			NsPerOp:     v[0].NsPerOp,
			BytesPerOp:  v[0].AllocedBytesPerOp,
			AllocsPerOp: v[0].AllocsPerOp,
		}
	}
	return res, nil
}

func cutRight(str string) string {
	for i := range len(str) {
		if str[len(str)-1-i] == '-' {
			return str[:len(str)-1-i]
		}
	}
	return ""
}

func plotsPerVer(data Result) map[string]map[string]*plot.Plot {
	plots := map[string]map[string]*plot.Plot{}
	for ver, mp := range data {
		plots[ver] = map[string]*plot.Plot{}
		for grp, mp := range mp {
			plots[ver][grp] = barPlot(grp, mp)
		}
	}
	return plots
}

func barPlot(title string, data map[string]Benchmark) *plot.Plot {
	// Order labels for consistency
	labels := make([]string, 0, len(data))
	for k := range data {
		labels = append(labels, k)
	}
	slices.Sort(labels)

	// Find the maxes
	var (
		maxNsPerOp     float64
		maxBPerOp      uint64
		maxAllocsPerOp uint64
	)
	for _, bench := range data {
		maxNsPerOp = max(maxNsPerOp, bench.NsPerOp)
		maxBPerOp = max(maxBPerOp, bench.BytesPerOp)
		maxAllocsPerOp = max(maxAllocsPerOp, bench.AllocsPerOp)
	}

	// Plot in log per the % of maxes
	ns := make(plotter.Values, len(labels))
	bytes := make(plotter.Values, len(labels))
	allocs := make(plotter.Values, len(labels))
	for i, label := range labels {
		ns[i] = scale((data[label].NsPerOp * 100) / maxNsPerOp)

		if maxBPerOp != 0 {
			bytes[i] = scale((float64(data[label].BytesPerOp) * 100) / float64(maxBPerOp)) // assume maxBPerOp is non-zero
		} else {
			bytes[i] = 0 // disable printing it for readability purposes
		}

		if maxAllocsPerOp != 0 {
			allocs[i] = scale((float64(data[label].AllocsPerOp) * 100) / float64(maxAllocsPerOp)) // assume maxAllocsPerOp is non-zero
		} else {
			allocs[i] = 0 // disable printing it for readability purposes
		}
	}

	// Plot all metrics
	p := plot.New()
	p.X.Label.Text = title
	p.X.Label.Position = draw.PosCenter
	p.X.Tick.Label.Rotation = 0.7
	p.X.Tick.Label.YAlign = draw.YTop
	p.X.Tick.Label.XAlign = draw.XRight
	p.NominalX(labels...)
	p.Y.Label.Text = "Log of % per the max value of this metric."

	// -2 to make a bit of light between the bars, lighter
	bNs, _ := plotter.NewBarChart(ns, barWidth-2)
	bBytes, _ := plotter.NewBarChart(bytes, barWidth-2)
	bAllocs, _ := plotter.NewBarChart(allocs, barWidth-2)

	bNs.Color = color.RGBA{66, 114, 197, 255}      // blue
	bBytes.Color = color.RGBA{230, 127, 52, 255}   // orange
	bAllocs.Color = color.RGBA{180, 182, 185, 255} // grey

	bNs.LineStyle.Width = 0
	bBytes.LineStyle.Width = 0
	bAllocs.LineStyle.Width = 0

	bNs.Offset = -barWidth
	bAllocs.Offset = barWidth

	p.Add(bNs)
	p.Add(bBytes)
	p.Add(bAllocs)

	p.Legend.Add("ns/op", bNs)
	p.Legend.Add("B/op", bBytes)
	p.Legend.Add("allocs/op", bAllocs)
	p.Legend.Top = true
	p.Legend.Left = false

	return p
}

func scale(v float64) float64 {
	return math.Log(max(v, 1)) // as log(1) == 0, don't enable <0 which would produce negative values + would make poor sense in benchmarks
}

func export(data Result, plots map[string]map[string]*plot.Plot) error {
	_ = os.RemoveAll("dist")
	_ = os.Mkdir("dist", os.ModePerm)

	f, err := os.Create(filepath.Join("dist", "benchmark.json"))
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "    ")
	if err := enc.Encode(data); err != nil {
		return err
	}

	for ver, plots := range plots {
		var (
			width  = 6 * vg.Inch * vg.Length(len(plots))
			height = 6 * vg.Inch
		)
		canvas := vgsvg.New(width, height)
		dc := draw.New(canvas)

		tiles := draw.Tiles{
			Rows: 1,
			Cols: len(plots),
		}

		// Order groups by alphabetic order for consistency
		grps := []string{}
		for grp := range plots {
			grps = append(grps, grp)
		}
		slices.Sort(grps)

		col := 0
		for _, grp := range grps {
			p := plots[grp]
			p.Draw(tiles.At(dc, col, 0))
			col++
		}

		f, err := os.Create(filepath.Join("dist", "benchmark-results-cvss-"+ver+".svg"))
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := canvas.WriteTo(f); err != nil {
			return err
		}
	}
	return nil
}

func fatal(err error) {
	fmt.Printf("[X] %s\n", err)
	os.Exit(1)
}
