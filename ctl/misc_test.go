package ctl

import (
	"reflect"
	"testing"
	"time"
)

func Test_parseDate(t *testing.T) {
	type args struct {
		date string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Time
		wantErr bool
	}{
		{
			name: "2022-09-02",
			args: args{
				date: "2022-09-02",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name: "2022-9-2",
			args: args{
				date: "2022-9-2",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name: "Sep 2, 2022",
			args: args{
				date: "Sep 2, 2022",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name: "Sep 02, 2022",
			args: args{
				date: "Sep 02, 2022",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name: "September 2, 2022",
			args: args{
				date: "September 2, 2022",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name: "September 02, 2022",
			args: args{
				date: "September 02, 2022",
			},
			want:    time.Date(2022, time.September, 2, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDate(tt.args.date)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDate() = %v, want %v", got, tt.want)
			}
		})
	}
}
