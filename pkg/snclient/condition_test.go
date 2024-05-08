package snclient

import (
	"fmt"
	"testing"

	"pkg/convert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionParse(t *testing.T) {
	for _, check := range []struct {
		input  string
		expect *Condition
	}{
		{"none", &Condition{isNone: true}},
		{"load > 95%", &Condition{keyword: "load", operator: Greater, value: "95", unit: "%"}},
		{"used > 90GB", &Condition{keyword: "used", operator: Greater, value: "90000000000", unit: "B"}},
		{"used>90B", &Condition{keyword: "used", operator: Greater, value: "90", unit: "B"}},
		{"used >= 90GiB", &Condition{keyword: "used", operator: GreaterEqual, value: "96636764160", unit: "B"}},
		{"state = dead", &Condition{keyword: "state", operator: Equal, value: "dead"}},
		{"uptime < 180s", &Condition{keyword: "uptime", operator: Lower, value: "180", unit: "s"}},
		{"uptime < 2h", &Condition{keyword: "uptime", operator: Lower, value: "7200", unit: "s"}},
		{"version not like  '1 2 3'", &Condition{keyword: "version", operator: ContainsNot, value: "1 2 3"}},
		{"state is not 0", &Condition{keyword: "state", operator: Unequal, value: "0"}},
		{"used gt 0", &Condition{keyword: "used", operator: Greater, value: "0"}},
		{"type = 'fixed'", &Condition{keyword: "type", operator: Equal, value: "fixed"}},
		{"type ='fixed'", &Condition{keyword: "type", operator: Equal, value: "fixed"}},
		{"type= 'fixed'", &Condition{keyword: "type", operator: Equal, value: "fixed"}},
		{"type='fixed'", &Condition{keyword: "type", operator: Equal, value: "fixed"}},
		{"command ~~ /ssh localhost/", &Condition{keyword: "command", operator: RegexMatchNoCase, value: "ssh localhost"}},
		{"command ~ /ssh localhost/i", &Condition{keyword: "command", operator: RegexMatchNoCase, value: "ssh localhost"}},
		{"command ~ /ssh localhost/", &Condition{keyword: "command", operator: RegexMatch, value: "ssh localhost"}},
		{"state not in ('started')", &Condition{keyword: "state", operator: NotInList, value: []string{"started"}}},
		{"state in ('a', 'b','c')", &Condition{keyword: "state", operator: InList, value: []string{"a", "b", "c"}}},
		{"state in ('a', 'b','c','d' )", &Condition{keyword: "state", operator: InList, value: []string{"a", "b", "c", "d"}}},
		{"state in ( 'a', 'b')", &Condition{keyword: "state", operator: InList, value: []string{"a", "b"}}},
		{
			"provider = 'abc' and id = 123 and message like 'foo'",
			&Condition{
				groupOperator: GroupAnd,
				group: ConditionList{
					{keyword: "provider", operator: Equal, value: "abc"},
					{keyword: "id", operator: Equal, value: "123"},
					{keyword: "message", operator: Contains, value: "foo"},
				},
			},
		},
		{
			"provider = 'abc' and (id = 123 or message like 'foo')",
			&Condition{
				groupOperator: GroupAnd,
				group: ConditionList{
					{keyword: "provider", operator: Equal, value: "abc"},
					{
						groupOperator: GroupOr,
						group: ConditionList{
							{keyword: "id", operator: Equal, value: "123"},
							{keyword: "message", operator: Contains, value: "foo"},
						},
					},
				},
			},
		},
	} {
		cond, err := NewCondition(check.input)
		check.expect.original = check.input
		require.NoErrorf(t, err, "ConditionParse should throw no error")
		assert.Equal(t, check.expect, cond, fmt.Sprintf("ConditionParse(%s) -> %v", check.input, check.expect))
	}
}

func TestConditionParseErrors(t *testing.T) {
	for _, check := range []struct {
		threshold string
		error     error
	}{
		{"val like", nil},
		{"val like '", nil},
		{"val like 'a", nil},
		{`val like "`, nil},
		{`val like "a`, nil},
		{"a > 5 and", nil},
		{"a >", nil},
		{"a 5", nil},
		{"> 5", nil},
		{"(a > 1 or b > 1", nil},
		{"((a > 1 or b > 1)", nil},
		{"a > 1 ) 1)", nil},
		{"state in ('a', 'b',)", nil},
		{"state in ('a', 'b',", nil},
		{"state in ('a', 'b'", nil},
		{"state in (", nil},
		{"a > 0 && b < 0 || x > 3", nil},
	} {
		cond, err := NewCondition(check.threshold)
		require.Errorf(t, err, "ConditionParse should error")
		assert.Nilf(t, cond, fmt.Sprintf("ConditionParse(%s) errors should not return condition", check.threshold))
	}
}

func TestConditionCompare(t *testing.T) {
	for _, check := range []struct {
		threshold     string
		key           string
		value         string
		expect        bool
		deterministic bool
	}{
		{"test > 5", "test", "2", false, true},
		{"test > 5", "test", "5.1", true, true},
		{"test >= 5", "test", "5.0", true, true},
		{"test < 5", "test", "5.1", false, true},
		{"test <= 5", "test", "5.0", true, true},
		{"test <= 5", "test", "5.1", false, true},
		{"test like abc", "test", "abcdef", true, true},
		{"test not like abc", "test", "abcdef", false, true},
		{"test like 'abc'", "test", "abcdef", true, true},
		{`test like "abc"`, "test", "abcdef", true, true},
		{"test ilike 'AbC'", "test", "aBcdef", true, true},
		{"test not ilike 'AbC'", "test", "aBcdef", false, true},
		{`test in ('abc', '123', 'xyz')`, "test", "123", true, true},
		{`test in ('abc', '123', 'xyz')`, "test", "13", false, true},
		{`test not in ('abc', '123', 'xyz')`, "test", "123", false, true},
		{`test in('abc', '123', 'xyz')`, "test", "123", true, true},
		{`test not in ('abc', '123', 'xyz')`, "test", "asd", true, true},
		{`test not in('abc', '123', 'xyz')`, "test", "asd", true, true},
		{`test not in('abc','123','xyz')`, "test", "asd", true, true},
		{`test NOT IN('abc','123','xyz')`, "test", "asd", true, true},
		{"test = 5", "test", "5", true, true},
		{"test = 5", "test", "5.0", true, true},
		{"test = 5.0", "test", "5", true, true},
		{"test = '123'", "test", "123", true, true},
		{"test != '123'", "test", "123", false, true},
		{"test regex 'a+'", "test", "aaaa", true, true},
		{"test regex 'a+'", "test", "bbbb", false, true},
		{"test !~ 'a+'", "test", "bbb", true, true},
		{"test !~ 'a+'", "test", "aa", false, true},
		{"test ~~ 'a'", "test", "AAAA", true, true},
		{"test ~~ 'a'", "test", "BBBB", false, true},
		{"test ~ /a/i", "test", "AAAA", true, true},
		{"test ~ '/a/i'", "test", "AAAA", true, true},
		{"test !~ /a/i", "test", "aaa", false, true},
		{"test !~~ 'a'", "test", "AAAA", false, true},
		{"test !~~ 'a'", "test", "BBBB", true, true},
		{"'test space' > 5", "test space", "2", false, true},
		{"'test space' < 5", "test space", "2", true, true},
		{"unknown unlike blah", "test", "blah", false, false},
		{"unknown like blah", "test", "blah", false, false},
		{"unknown unlike blah or test like blah", "test", "blah", true, true},
		{"unknown like blah or test unlike blah", "test", "blah", false, false},
		{"unknown unlike blah and test like blah", "test", "blah", false, false},
		{"unknown like blah and test unlike blah", "test", "blah", false, true},
	} {
		threshold, err := NewCondition(check.threshold)
		require.NoErrorf(t, err, "parsed threshold")
		assert.NotNilf(t, threshold, "parsed threshold")
		compare := map[string]string{check.key: check.value}
		res, ok := threshold.Match(compare)
		assert.Equalf(t, check.expect, res, fmt.Sprintf("Compare(%s) -> (%v) %v", check.threshold, check.value, check.expect))
		assert.Equalf(t, check.deterministic, ok, fmt.Sprintf("Compare(%s) -> determined: (%v) %v", check.threshold, check.value, check.deterministic))
	}
}

func TestConditionThresholdString(t *testing.T) {
	for _, check := range []struct {
		threshold string
		name      string
		expect    string
	}{
		{"test > 5", "test", "5"},
		{"test > 5 or test < 3", "test", "3:5"},
		{"test < 3 or test > 5", "test", "3:5"},
		{"test > 10 and test < 20", "test", "@10:20"},
		{"test < 20 and test > 10", "test", "@10:20"},
	} {
		threshold, err := NewCondition(check.threshold)
		require.NoErrorf(t, err, "parsed threshold")
		assert.NotNilf(t, threshold, "parsed threshold")
		perfRange := ThresholdString([]string{check.name}, ConditionList{threshold}, convert.Num2String)
		assert.Equalf(t, check.expect, perfRange, fmt.Sprintf("ThresholdString(%s) -> (%v) = %v", check.threshold, perfRange, check.expect))
	}
}
