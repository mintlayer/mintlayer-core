import argparse
import csv
import mplcursors
import pathlib
from collections import namedtuple
from matplotlib import pyplot


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR.joinpath("output")
DEFAULT_INPUT_FILE = OUTPUT_DIR.joinpath("mainnet_block_timestamps_targets.csv")
AVERAGE_BLOCKS_PER_DAY = 720

CLICK_TO_SHOW_TOOLTIP_TEXT = "click to show a tooltip (can be laggy)"


class Handler():
    def __init__(self, args):
        loaded_data = load_data(args.input_file)

        self.all_targets = loaded_data.targets_since_block1
        self.all_time_diffs = (
            [t2 - t1 for t1, t2 in
                zip(loaded_data.timestamps_since_block0,
                    loaded_data.timestamps_since_block0[1:])]
        )

        # Note:
        # self.all_targets[N] corresponds to the block at height N+1.
        # self.all_time_diffs[N] is the timestamp difference between blocks at heights N+1 and N.

        if args.recent_days is None:
            self.skipped_blocks = 0
            self.block_range_help_str = "entire history"
        else:
            last_blocks_to_show = min(args.recent_days * AVERAGE_BLOCKS_PER_DAY, len(self.all_targets))
            self.skipped_blocks = len(self.all_targets) - last_blocks_to_show
            self.block_range_help_str = f"last {args.recent_days} days"

        self.targets = self.all_targets[self.skipped_blocks:]
        self.time_diffs = self.all_time_diffs[self.skipped_blocks:]
        self.starting_height = self.skipped_blocks + 1

    def run(self):
        print("Creating plots")
        self.plot_targets()
        self.plot_time_diffs()
        print("Plots created")

        pyplot.show()

    def plot_targets(self):
        figure, axes = pyplot.subplots(layout="constrained")
        figure.canvas.manager.set_window_title(f"Targets, {self.block_range_help_str}")

        plot = scatter_from(
            axes,
            self.targets,
            self.starting_height,
            s=1,
        )

        # Note: the initial targets were very big, so if the entire range is plotted,
        # the later difficulties will be hard to distinguish, unless we set the limit
        # for the y axis values.
        #
        # Note: normal_y_lim is close to what is used by default, it leaves some space at
        # the top of the plot to make it look better.
        normal_y_lim = float(max(self.targets)) * 1.05
        y_lim = min(float(self.all_targets[20000]), normal_y_lim)
        axes.set_ylim(bottom=0, top=y_lim)

        # For some reason, zero values on the axes are shifted to the right/top by default.
        # For the y axis we've fixed it already by specifying bottom=0 above, now do the same
        # for the x axis.
        axes.set_xlim(left=self.skipped_blocks)

        axes.set_xlabel("Block height")
        axes.set_ylabel("Target")
        axes.set_title(f"Target plot, {CLICK_TO_SHOW_TOOLTIP_TEXT}", fontdict={'fontweight': 'bold'})

        # Show the height as an integer
        Handler.set_tooltips(plot, "height = {x:.0f}\ntarget = {y:.2e}s")

    def plot_time_diffs(self):
        figure, axes = pyplot.subplots(layout="constrained")
        figure.canvas.manager.set_window_title(f"Timestamp differences, {self.block_range_help_str}")

        plot = scatter_from(
            axes,
            self.time_diffs,
            self.starting_height,
            s=9,
        )

        axes.set_xlabel("Block height")
        axes.set_ylabel("Difference between timestamps of this and the previous block, in seconds")
        axes.set_title(f"Timestamp diff plot, {CLICK_TO_SHOW_TOOLTIP_TEXT}", fontdict={'fontweight': 'bold'})

        # Show the values as integers.
        Handler.set_tooltips(plot, "height = {x:.0f}\ntime diff = {y:.0f}s")

        average_time_diff = sum(self.time_diffs)/len(self.time_diffs)
        min_time_diff = min(self.time_diffs)
        max_time_diff_idx = max_value_idx(self.time_diffs)
        max_time_diff_height = self.starting_height + max_time_diff_idx
        max_time_diff = self.time_diffs[max_time_diff_idx]

        top_left_text = f"Min diff: {min_time_diff}s"

        top_left_text += f"\nMax diff: {max_time_diff}s, block {max_time_diff_height}"
        if self.skipped_blocks != 0:
            all_time_max = max(self.all_time_diffs)
            top_left_text += f" (all time max: {all_time_max}s)"

        top_left_text += f"\nAverage diff: {average_time_diff:.3f}s"
        if self.skipped_blocks != 0:
            all_time_average = sum(self.all_time_diffs)/len(self.all_time_diffs)
            top_left_text += f" (all time average: {all_time_average:.3f}s)"

        axes.text(0.01, 0.99, top_left_text, transform=axes.transAxes, ha="left", va="top", fontsize=12)

    # Here text_fmt is a format string, it must refer to the values as 'x' and 'y'.
    @staticmethod
    def set_tooltips(plot, text_fmt):
        cursor = mplcursors.cursor(plot, hover=False)

        def cursor_add_handler(sel):
            x, y = sel.target
            text = text_fmt.format(x=x, y=y)
            sel.annotation.set_text(text)
            # Align the contents to the left (note that "horizontalalignment" aka "ha" only
            # works for the entire text box, so individual text lines won't be affected by it).
            sel.annotation.set_multialignment("left")
            # Make the background non-transparent (it's hard to see otherwise).
            sel.annotation.get_bbox_patch().set(alpha=1.)

        cursor.connect("add", cursor_add_handler)


def scatter_from(axes, y_vals, x_start, **kwargs):
    return axes.scatter(
        range(x_start, x_start + len(y_vals)),
        y_vals,
        **kwargs
    )


LoadedData = namedtuple("LoadedData", ["timestamps_since_block0", "targets_since_block1"])


def load_data(input_file):
    print(f"Reading input data from {input_file}")

    with open(input_file, 'r') as file:
        csv_reader = csv.reader(file)

        header = next(csv_reader)
        assert header == ["height", "timestamp", "target"], f"Unexpected CSV header: {header}"

        # For genesis, the target will be bogus (a dash).
        (genesis_height, genesis_timestamp, _) = next(csv_reader)
        assert int(genesis_height) == 0, f"Unexpected height at first line: {genesis_height}"

        timestamps_since_block0 = [int(genesis_timestamp)]
        targets_since_block1 = []
        prev_height = 0

        for height, timestamp, target in csv_reader:
            height = int(height)
            assert height == prev_height + 1, f"Unexpected height {height}, prev height was {prev_height}"
            prev_height = height

            timestamps_since_block0.append(int(timestamp))
            targets_since_block1.append(int(target, 16))

        return LoadedData(
            timestamps_since_block0=timestamps_since_block0,
            targets_since_block1=targets_since_block1
        )


def max_value_idx(list):
    return max(enumerate(list), key=lambda item: item[1])[0]


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--input-file",
        help="Input file produced by collect_data.py",
        default=DEFAULT_INPUT_FILE)
    parser.add_argument("--recent-days",
        type=int,
        help='If specified, only plot the block data corresponding to this number of recent days (approximately)')
    args = parser.parse_args()

    Handler(args).run()


if __name__ == "__main__":
    main()
