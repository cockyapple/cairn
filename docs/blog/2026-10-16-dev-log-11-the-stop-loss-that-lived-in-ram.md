# Dev log 11: the stop-loss that lived in RAM, and the AI that had no edge

*Part 14 of the Cairn series. This one is off the main road: it is about the paper-trading stock funds that run on the same home server as the rest of this work. I asked a panel of AI models why the funds never sold their losers and how to make them profitable. The answer was not the one I expected, and part of it was my own mistake. This is all paper money, and nothing here is financial advice.*

## The question

The funds are simulated. Each one holds a basket of picks chosen by a council of AI models, and none of it involves real money. I noticed that stocks down 30 percent were still held, and stocks up a lot were never trimmed. I asked, more or less, why the AI was not smarter than a person with a stop-loss. Then I asked for a plan to make the funds as profitable as possible.

## What the council found

I put the numbers in front of five models and asked for a diagnosis. Two findings stood out.

- **The AI verdict has no edge.** Over seven days, stocks the council called BULLISH returned an average of -0.31 percent. Stocks it called BEARISH returned +4.59 percent. The signal pointed the wrong way, if anything.
- **The AI-picked funds lost money while a dull basket made it.** The active funds were down between 5.7 and 7.1 percent. A basket of the largest US companies with no AI involved at all was up about 10 percent over the same stretch.

That is an unflattering result for the part of the system I was proudest of. I am reporting it as it came out.

## The real reason nothing was sold

The exit logic existed. A script called `position-risk-check.sh` checks every position against a stop-loss and a take-profit level. It was never the AI's job to sell, and the AI was not at fault for the missing sales.

The cron line that ran the script lived only in the running crontab. This server keeps its root filesystem in RAM, so anything not saved to the USB flash is wiped at every reboot. The line vanished at a reboot, the script stopped running, and nothing noticed. The last effective run was around August 25.

When I ran it by hand, four stops that were weeks overdue executed immediately.

This is the same class of bug I have now hit several times on this host: a thing that works, is never written down in the place that survives a reboot, and fails silently. The fix has two halves.

1. The schedule is now a file on persistent storage that is installed at boot.
2. The script writes a heartbeat each time it completes, and a separate watcher raises an alert if the heartbeat is stale. A job that dies quietly is the one case a job cannot report itself, so something else has to be watching for the silence.

## My own mistake: the clock

I scheduled the first version of the risk check as if the server ran on UTC. It runs on local time (Pacific). The runs I had planned for the afternoon would have fired after the market closed, so they would have priced everything at stale closing values. I caught it while reading the crontab back against the market hours, and moved the runs to 09:35, 12:35 and 13:35 local time, with the watcher at 14:00.

## Data traps

I then built a set of rule-based funds, with no AI picking stocks at all. Building the candidate lists meant trusting data I had not checked, and it was wrong in four ways.

- **Foreign market caps are garbage.** Several foreign companies listed as US depositary receipts showed absurd market caps and ranked as giants. I now cross-check each market cap against a second source and drop any name that disagrees by more than 25 percent.
- **Preferred shares pass as stocks.** The first run of the "largest companies" fund picked two Alphabet entries that turned out to be preferred depositary shares, not the common stock. I now filter out names containing words like depositary, preferred, warrant, notes and units, and keep one share class per company.
- **The biggest companies were missing.** Apple, Nvidia, Tesla and several others were absent from the universe because they had no price-history rows or scoring rows. An inner join quietly removed exactly the names a large-cap fund must hold. They are now left-joined.
- **Three models agreeing is not proof.** An earlier code audit by three different models agreed on a finding that turned out to be false when I checked it against live data. I verify against the real data before acting on any review, however unanimous.

## The Rules funds

Five funds start on Monday, October 19, each with $1,000 and then $50 per week.

| Fund | What it holds |
|---|---|
| Core | A broad market index fund |
| Market | The 25 largest US companies |
| Elite | Momentum plus quality, at most three names per sector |
| Global | US-listed foreign companies |
| Penny | Small caps, with a wider stop |

The weekly $50 goes to whichever target is furthest below its weight, so the fund never has to sell to rebalance. A monthly review sells names that fell out of the ranking. A stopped-out ticker cannot be bought again for 60 days, and each fund charges its own simulated trading cost.

Every deposit is also invested in the S&P 500 index in a shadow account. That gives each fund a plain benchmark to beat. If a fund cannot beat simply buying the index with the same cash on the same days, it has no reason to exist.

## What I expect

The council was candid about this, and so am I. These funds are built to behave like the market, with sensible exits and no fashionable AI signal on top. I expect market-like returns, not big profits. If a fund beats the shadow account after a month or two, that is a pleasant surprise. If none does, the honest conclusion is to buy the index.

I will compare them to the shadow after about four weeks and post the result either way.

## Lessons

The first lesson is about where to look. I asked why the AI was not smarter, and the problem was a missing line in a crontab. A check on whether the plumbing runs came before any question about the intelligence.

The second is that a safety mechanism needs its own alarm. A stop-loss that dies silently is worse than none, because you believe you have one.

The repository is at github.com/cockyapple/cairn.
