# Data
- Default: synthetic surrogate (seed 42, 6000 flows) — no download needed, fully reproducible.
- Optional real: `data/Wednesday-workingHours.pcap_ISCX.csv` (CIC-IDS2017 Wednesday, ~692k flows, 80.3% benign).
  Official: https://www.unb.ca/cic/datasets/ids-2017.html
  Kaggle mirrors: https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset
                  https://www.kaggle.com/datasets/hohnghong/cicids2017
                  https://www.kaggle.com/datasets/yasiralifarrukh/unsw-and-cicids2017-labelled-pcap-data
- UNSW-NB15 pointers: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Code auto-detects `data/*.csv`; schema-guard falls back to synth if columns drift (see gitmcp note).
- Never commit real CSV (large); results/*.json are the published artifacts.
